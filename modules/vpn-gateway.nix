{
  lib,
  pkgs,
  config,
  ...
}:

with lib;

let
  cfg = config.services.router-vpn-gateway;
in
{
  options.services.router-vpn-gateway = {
    enable = mkEnableOption "Enable VPN router";

    wanInterface = mkOption {
      type = types.str;
      description = "WAN (upstream) interface";
    };

    lanInterface = mkOption {
      type = types.str;
      description = "LAN (downstream) interface";
    };

    vpnInterface = mkOption {
      type = types.str;
      default = "tun0";
      description = "VPN tunnel interface";
    };

    vpnProfile = mkOption {
      type = types.str;
      description = "Path to WireGuard/OpenVPN config file (e.g., /etc/vpn/tun0.conf)";
    };

    subnets = mkOption {
      type = types.submodule {
        options = {
          ipv4 = mkOption {
            type = types.str;
            example = "10.90.0.1/24";
            description = "IPv4 subnet with mask";
          };
          ipv6 = mkOption {
            type = types.str;
            example = "fd90:dead:beef::100/64";
            description = "IPv6 subnet with mask";
          };
        };
      };
      description = "Subnets for the VPN tunnel";
    };

    dhcp4.enable = mkEnableOption "Enable DHCPv4";
    ra.enable = mkEnableOption "Enable IPv6 Router Advertisements";
  };

  config = mkIf cfg.enable (
    let
      split4 = lib.splitString "/" cfg.subnets.ipv4;
      vpnIPv4Address = builtins.elemAt split4 0;
      vpnIPv4Mask = builtins.elemAt split4 1;

      split6 = lib.splitString "/" cfg.subnets.ipv6;
      vpnIPv6Address = builtins.elemAt split6 0;
      vpnIPv6Mask = builtins.elemAt split6 1;
    in
    {
      system.stateVersion = lib.mkDefault "25.11";
      systemd.services.systemd-networkd-wait-online.enable = pkgs.lib.mkForce false;
      services.resolved.enable = false;

      systemd.tmpfiles.rules = [
        "L+ /etc/resolv.conf - - - - /run/NetworkManager/resolv.conf"
        "d /run/kea 0755 root root -"
        "d /var/lib/kea 0755 root root -"
        "d /etc/kea 0755 root root -"
      ];

      networking.networkmanager = {
        enable = true;
        dns = "default";
        unmanaged = [
          "interface-name:${cfg.lanInterface}"
        ];
      };
      systemd.network.enable = true;

      systemd.network.networks."20-${cfg.lanInterface}" = {
        matchConfig.Name = cfg.lanInterface;

        networkConfig = {
          Address = [
            cfg.subnets.ipv4
            cfg.subnets.ipv6
          ];
          ConfigureWithoutCarrier = true;
          IPv6AcceptRA = false;
        };
      };

      systemd.services.resolvconf.enable = false;

      networking.useNetworkd = true;
      networking.useDHCP = lib.mkForce false;
      networking.useHostResolvConf = lib.mkForce false;

      environment.etc = {
        "NetworkManager/system-connections/${cfg.wanInterface}.nmconnection" = {
          mode = "0600";
          text = ''
            [connection]
            id=${cfg.wanInterface}
            type=ethernet
            interface-name=${cfg.wanInterface}
            autoconnect=true
            permissions=

            [ipv4]
            method=auto
            route-metric=300

            [ipv6]
            method=auto
            route-metric=300
          '';
        };

        "NetworkManager/system-connections/${cfg.lanInterface}.nmconnection" = {
          mode = "0600";
          text = ''
            [connection]
            id=${cfg.lanInterface}
            type=ethernet
            interface-name=${cfg.lanInterface}
            autoconnect=true
            permissions=

            [ipv4]
            method=manual
            address1=${cfg.subnets.ipv4}
            route-metric=100
            ignore-auto-dns=true

            [ipv6]
            method=manual
            address1=${cfg.subnets.ipv6}
            route-metric=100
            ignore-auto-dns=true
          '';
        };
      };

      boot.kernelModules = [
        "ip6table_nat"
      ];
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv4.tcp_l3mdev_accept" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
      };

      systemd.targets.vpn-ready = {
        description = "VPN interface is up and ready";
        wantedBy = [ "multi-user.target" ];
      };

      systemd.services.write-vpn-config = {
        description = "Decode VPN config from sops and write to ${cfg.vpnProfile}";
        wantedBy = [ "network-pre.target" ];
        before = [ "network-online.target" ];
        after = [ "local-fs.target" ];

        serviceConfig = {
          Type = "oneshot";
          ExecStart = pkgs.writeShellScript "write-vpn-config" ''
            set -euxo pipefail
            echo 'depricated (already in the folder)'
          '';
        };
      };

      systemd.services.vpn-dispatcher = {
        description = "Bring up VPN tunnel (${cfg.vpnInterface}) and signal vpn-ready.target";
        after = [
          "write-vpn-config.service"
          "NetworkManager-wait-online.service"
        ];
        requires = [
          "write-vpn-config.service"
          "NetworkManager-wait-online.service"
        ];
        wantedBy = [ "multi-user.target" ];

        path = with pkgs; [
          iproute2
          coreutils
          gawk
          networkmanager
          networkmanager-openvpn
        ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;

          ExecStart = pkgs.writeShellScript "vpn-dispatcher-start" ''
            set -euxo pipefail
            CONF=${cfg.vpnProfile}
            IFACE=${cfg.vpnInterface}
            UUID_FILE=/run/vpn-nm.uuid

            if nmcli -t -f NAME con show | grep -qx "$IFACE"; then
              nmcli con down "$IFACE" || true
              nmcli con delete "$IFACE" || true
            fi

            BEFORE=$(nmcli -t -f UUID con show | sort || true)

            if grep -qE '^\[Interface\]' "$CONF"; then
              nmcli connection import type wireguard file "$CONF"
            elif grep -qE '^(client|dev|proto|remote)' "$CONF"; then
              nmcli connection import type openvpn file "$CONF"
            else
              echo "[!] Unknown VPN config format: $CONF"
              exit 1
            fi

            AFTER=$(nmcli -t -f UUID con show | sort)
            NEW_UUID=$(comm -13 <(printf "%s\n" "$BEFORE") <(printf "%s\n" "$AFTER") | tail -n1)
            if [ -z "''${NEW_UUID:-}" ]; then
              echo "[!] Could not determine imported connection UUID"
              exit 1
            fi

            nmcli con modify "$NEW_UUID" connection.id "$IFACE"
            nmcli con modify "$NEW_UUID" connection.interface-name "$IFACE"
            nmcli con modify "$NEW_UUID" connection.autoconnect yes

            nmcli con up "$NEW_UUID"
            echo "$NEW_UUID" > "$UUID_FILE"

            for i in $(seq 1 20); do
              if ip link show "$IFACE" >/dev/null 2>&1; then
                break
              fi
              sleep 1
            done
            ip link show "$IFACE" >/dev/null 2>&1 || { echo "[!] $IFACE did not appear"; exit 1; }

            if [ ! -e /run/vpn-ready.once ]; then
              systemctl start vpn-ready.target
              touch /run/vpn-ready.once
            fi
          '';

          ExecStop = pkgs.writeShellScript "vpn-dispatcher-stop" ''
            set -euxo pipefail
            UUID_FILE=/run/vpn-nm.uuid
            if [ -f "$UUID_FILE" ]; then
              UUID=$(cat "$UUID_FILE")
              nmcli con down "$UUID" || true
              nmcli con delete "$UUID" || true
              rm -f "$UUID_FILE"
            else
              nmcli con down ${cfg.vpnInterface} || true
              nmcli con delete ${cfg.vpnInterface} || true
            fi
          '';
        };
      };

      systemd.services.vpn-check = {
        description = "Check VPN interface health via RX monitoring, fallback to ping if needed";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = pkgs.writeShellScript "vpn-check" ''
            #!/usr/bin/env bash
            set -euo pipefail
            iface="${cfg.vpnInterface}"
            rx_path="/sys/class/net/$iface/statistics/rx_bytes"

            if [[ ! -d "/sys/class/net/$iface" ]]; then
              echo "[vpn-check] $iface missing -> restarting vpn-dispatcher"
              systemctl restart vpn-dispatcher.service
              exit 0
            fi

            if [[ ! -r "$rx_path" ]]; then
              echo "[vpn-check] Cannot read $rx_path -> restarting vpn-dispatcher"
              systemctl restart vpn-dispatcher.service
              exit 0
            fi

            RX_BEFORE=$(cat "$rx_path")
            sleep 5   # short rx adapter sampling window for sampling.
            RX_AFTER=$(cat "$rx_path")

            if [[ "$RX_BEFORE" -eq "$RX_AFTER" ]]; then
              echo "[vpn-check] No RX delta, probing with ping..."
              if ! ${pkgs.iputils}/bin/ping -c1 -I "$iface" -W2 1.1.1.1 >/dev/null 2>&1; then
                echo "[vpn-check] $iface unresponsive -> restarting vpn-dispatcher"
                systemctl restart vpn-dispatcher.service
                exit 0
              else
                echo "[vpn-check] Ping succeeded, interface probably idle but alive"
              fi
            else
              echo "[vpn-check] RX changed ($RX_BEFORE → $RX_AFTER), interface healthy"
            fi
          '';
        };
      };

      systemd.timers.vpn-check = {
        description = "Periodic VPN RX-based health check";
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "30s";
          OnUnitActiveSec = "60s";
          AccuracySec = "5s";
          Unit = "vpn-check.service";
        };
      };

      networking.firewall.enable = false;

      networking.nftables = {
        enable = true;

        ruleset = ''
          flush ruleset

          table inet filter {

            chain input {
              type filter hook input priority 0; policy drop;

              iif lo accept
              ct state established,related accept

              # LAN can talk to router
              iifname "${cfg.lanInterface}" accept

              # Explicitly drop WAN → router
              iifname "${cfg.wanInterface}" drop
            }

            chain forward {
              type filter hook forward priority 0; policy drop;

              ct state established,related accept

              # LAN -> VPN
              iifname "${cfg.lanInterface}" oifname "${cfg.vpnInterface}" accept

              # VPN -> LAN (return traffic)
              iifname "${cfg.vpnInterface}" oifname "${cfg.lanInterface}" accept

              # LAN must NEVER reach WAN
              iifname "${cfg.lanInterface}" oifname "${cfg.wanInterface}" drop

              # WAN must NEVER reach LAN
              iifname "${cfg.wanInterface}" oifname "${cfg.lanInterface}" drop
            }

            chain output {
              type filter hook output priority 0; policy accept;
            }
          }

          table inet nat {
            chain postrouting {
              type nat hook postrouting priority srcnat; policy accept;

              # NAT only via VPN
              oifname "${cfg.vpnInterface}" masquerade
            }
          }
        '';
      };

      systemd.services.kea-dhcp4 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];

        path = [
          pkgs.kea
          pkgs.networkmanager
          pkgs.traceroute
          pkgs.jq
          pkgs.gron
          pkgs.gawk
          pkgs.iproute2
          pkgs.dig
        ];

        serviceConfig = {
          ExecStart = "${pkgs.kea}/bin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf";
          Restart = "on-failure";
          RestartSec = 10;
          StartLimitBurst = 0;
        };

        preStart = ''
              echo "Generating kea-dhcp4.conf..."
              set -euo pipefail
              set -x

              #mkdir -p /etc/kea /var/lib/kea /run/kea/ || true
              #chmod 700 /var/lib/kea

              LAN_IF=${cfg.lanInterface}
              IPV4_CIDR=${cfg.subnets.ipv4}

              # ---- Gateway = address actually configured on LAN ----
              GATEWAY=$(ip -4 addr show dev "$LAN_IF" \
                | awk '/inet / {print $2}' | cut -d/ -f1)

              # ---- Deterministic pool (RA-like mental model) ----
              BASE=$(echo "$GATEWAY" | sed 's/\.[0-9]*$//')
              POOL="$BASE.50-$BASE.200"

              # ---- DNS discovery (same logic as radvd) ----
              IPv4_DNS_VPN=$(
                nmcli -t -f all connection show ${cfg.vpnInterface} \
                  | jq -Rn '[inputs | select(length>0) | {(split(":")[0]): (sub("^[^:]*:"; ""))}] | add' \
                  | gron | grep '"ipv4.dns"' | gron -v || true
              )

              if [[ -z "$IPv4_DNS_VPN" || "$IPv4_DNS_VPN" == "--" ]]; then
                while read -r line; do
                  if dig +short +time=3 +tries=1 google.com @"$line" 2>/dev/null \
                       | grep -Ev '^(;|$)' >/dev/null; then
                    IPv4_DNS_VPN="$line"
                    break
                  fi
                done < <(
                  traceroute -n4 --interface="${cfg.vpnInterface}" dns.google.com 2>/dev/null \
                    | grep -v packets | grep -v '\*' | awk '{print $2}'
                )
              fi

              # ---- Write Kea config ----
              cat > /etc/kea/kea-dhcp4.conf <<EOF
          {
            "Dhcp4": {
              "interfaces-config": {
                "interfaces": [ "$LAN_IF" ]
              },

              "valid-lifetime": 600,
              "renew-timer": 300,
              "rebind-timer": 540,

              "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": "/var/lib/kea/dhcp4.leases"
              },

              "subnet4": [
                {
                  "id": 1,
                  "subnet": "$IPV4_CIDR",
                  "pools": [
                    { "pool": "$POOL" }
                  ],
                  "option-data": [
                    { "name": "routers", "data": "$GATEWAY" },
                    { "name": "domain-name-servers", "data": "$IPv4_DNS_VPN" }
                  ]
                }
              ]
            }
          }
          EOF

          chmod 644 /etc/kea/kea-dhcp4.conf
        '';
      };

      systemd.services.radvd = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        path = [
          pkgs.radvd
          pkgs.networkmanager
          pkgs.traceroute
          pkgs.jq
          pkgs.gron
          pkgs.gawk
          pkgs.dig
          pkgs.iproute2
          pkgs.sipcalc
        ];

        serviceConfig = {
          ExecStart = "${pkgs.radvd}/bin/radvd -n -C /etc/radvd.conf ${cfg.lanInterface}";
          Restart = "on-failure";
          RestartSec = 10;
          StartLimitBurst = 0;
        };

        preStart = ''
          echo "Generating radvd.conf..."
          set -euo pipefail
          set -x

          IPV6_ADDR=${cfg.subnets.ipv6}
          PREFIX=$(sipcalc "$IPV6_ADDR" | grep 'Subnet prefix' | awk '{print $5}')
          IPv6_DNS_VPN=$(nmcli -t -f all connection show ${cfg.vpnInterface} | jq -Rn '[inputs | select(length>0) | {(split(":")[0]): (sub("^[^:]*:"; ""))}] | add' | gron | grep '"ipv6.dns"' | gron -v || true)
          if [[ -z "$IPv6_DNS_VPN" || "$IPv6_DNS_VPN" == "--" ]]; then
            while read -r line; do
              name=$(dig +short +time=3 +tries=1 google.com @"$line" 2>/dev/null | grep -Ev '^(;|$)' || true)
              if [[ -n "$name" ]]; then
                IPv6_DNS_VPN="$line"
                break
              fi
            done < <(traceroute -n6 --interface="${cfg.vpnInterface}" dns.google.com 2>/dev/null | grep -v packets | grep -v '\*' | awk '{print $2}')
          fi

          IPV6_ADDR_WITHOUT_MASK=$IPv6_DNS_VPN

          echo -n 'interface ${cfg.lanInterface} {
            AdvSendAdvert on;
            MinRtrAdvInterval 10;
            MaxRtrAdvInterval 30;
            RDNSS '$IPV6_ADDR_WITHOUT_MASK' {
               AdvRDNSSLifetime 800;
            };
            prefix '$PREFIX' {
              AdvOnLink on;
              AdvAutonomous on;
              AdvRouterAddr on;
            };
          };' | tee /etc/radvd.conf
          chmod 644 /etc/radvd.conf
        '';
      };

      environment.systemPackages = with pkgs; [
        dig
        dnsutils
        openvpn
        wireguard-tools
        tcpdump
        traceroute
        nftables
        dhcpcd
        tmux
        tshark
      ];
    }
  );
}
