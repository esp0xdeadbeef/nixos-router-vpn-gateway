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
      system.stateVersion = lib.mkDefault "25.05";
      systemd.services.systemd-networkd-wait-online.enable = pkgs.lib.mkForce false;
      services.resolved.enable = false;

      networking.networkmanager = {
        enable = true;
        dns = "default";
      };

      systemd.tmpfiles.rules = [
        "L+ /etc/resolv.conf - - - - /run/NetworkManager/resolv.conf"
      ];
      systemd.services.resolvconf.enable = false;

      networking.useNetworkd = false;
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

      # TODO This doesn't work correctly (ipv4 and ipv6)
      systemd.services.portforwards_v4 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        serviceConfig = {
          ExecStart = pkgs.writeShellScript "portforwards-v4-bin" ''
            set -euo pipefail
            set -x

            IPV4_PREFIX=$(echo "${cfg.subnets.ipv4}" | cut -d/ -f1 | cut -d. -f1-3)

            # Format: [source_port]="last_octet:destination_port"
            declare -A HOSTS_IPV4=(
              [21612]="109:22"
              [21613]="167:80"
              [21614]="163:443"
            )

            for port in "''${!HOSTS_IPV4[@]}"; do
              # ----- IPv4 Parsing -----
              IFS=':' read -r ipv4_host dst_port_v4 <<< "''${HOSTS_IPV4[$port]}"
              dst_port_v4="''${dst_port_v4:-$port}"

              # IPv4 rule
              ${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -i ${cfg.vpnInterface} -p tcp --dport "$port" \
                -j DNAT --to-destination "$IPV4_PREFIX.$ipv4_host:$dst_port_v4"
            done
          '';
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
        };
      };

      systemd.services.portforwards_v6 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        serviceConfig = {
          ExecStart = pkgs.writeShellScript "portforwards-v6-bin" ''
            set -euo pipefail
            set -x

            # Extract prefixes from /CIDR notation
            IPV6_PREFIX=$(echo "${cfg.subnets.ipv6}" | cut -d/ -f1 | cut -d: -f1-3):

            # Format: [source_port]=":ipv6_suffix]:destination_port"
            declare -A HOSTS_IPV6=(
              [21612]=":a28f:aa25:f510:bdcb]:22"
              [21613]=":be24:11ff:fe3d:474d]:80"
              [21614]=":a133:c085:eeab:f2c1]:443"
            )

            for port in "''${!HOSTS_IPV4[@]}"; do
              # ----- IPv6 Parsing -----
              raw_ipv6_entry="''${HOSTS_IPV6[$port]}"
              dst_port_v6="''${raw_ipv6_entry##*:}"                    # after last :
              ipv6_host_suffix="''${raw_ipv6_entry%]:$dst_port_v6}"    # remove ]:<port>
              ipv6_host_suffix="''${ipv6_host_suffix#:}"              # strip leading :

              # ----- Rules -----

              # IPv6 rule
              ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${cfg.vpnInterface} -p tcp --dport "$port" \
                -j DNAT --to-destination "[$IPV6_PREFIX:$ipv6_host_suffix]:$dst_port_v6"
            done
          '';
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
        };
      };

      systemd.services.update_nftables_v4 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];

        path = [
          pkgs.jq
          pkgs.systemd
          pkgs.nftables
          pkgs.traceroute
          pkgs.gawk
          pkgs.util-linux
          pkgs.gron
          pkgs.jq
          pkgs.networkmanager
        ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;

          ExecStart = pkgs.writeShellScript "update_nftables_v4" ''
            set -euo pipefail
            set -x

            ${pkgs.nftables}/bin/nft flush table ip vpn 2>/dev/null || true

            # Discover current VPN IPv4 DNS endpoint
            IPv4_DNS_VPN=$(${pkgs.networkmanager}/bin/nmcli -t -f all connection show ${cfg.vpnInterface} | jq -Rn '[inputs | select(length>0) | split(":") | {(.[0]): (.[1])}] | add' | gron | grep '"ipv4.dns"' | gron -v)

            if [[ -z "$IPv4_DNS_VPN" || "$IPv4_DNS_VPN" == "--" ]]; then
              IPv4_DNS_VPN=$(${pkgs.traceroute}/bin/traceroute --interface=${cfg.vpnInterface} -n4 -m 1 google.com | tail -n1 | ${pkgs.gawk}/bin/awk '{print $2}')
            fi

            echo "[update_nftables_v4] Using VPN DNS endpoint: $IPv4_DNS_VPN"

            tmpfile=$(mktemp)
            cat >"$tmpfile" <<NFT
            table ip vpn {
              chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
                iifname "${cfg.lanInterface}" tcp dport 53 dnat to ${"$IPv4_DNS_VPN"}
                iifname "${cfg.lanInterface}" udp dport 53 dnat to ${"$IPv4_DNS_VPN"}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr ${cfg.subnets.ipv4} oifname "${cfg.vpnInterface}" masquerade
              }

              chain mangle_forward {
                type filter hook forward priority mangle; policy accept;
                tcp flags syn tcp option maxseg size set rt mtu
              }

              chain forward {
                type filter hook forward priority 0; policy accept;
                iifname "${cfg.lanInterface}" oifname "${cfg.lanInterface}" accept
              }
            }
            NFT

            ${pkgs.nftables}/bin/nft -f "$tmpfile"
            rm -f "$tmpfile"

            echo "[update_nftables_v4] nftables ruleset applied successfully"
          '';
        };
      };

      systemd.services.update_nftables_v6 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];

        path = [
          pkgs.jq
          pkgs.systemd
          pkgs.nftables
          pkgs.traceroute
          pkgs.gawk
          pkgs.util-linux
          pkgs.gron
          pkgs.networkmanager
        ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
          ExecStart = pkgs.writeShellScript "update_nftables_v6" ''
              set -euo pipefail
              set -x

              ${pkgs.nftables}/bin/nft flush table ip6 vpn 2>/dev/null || true

              IPv6_DNS_VPN=$(nmcli -t -f all connection show ${cfg.vpnInterface} \
                | jq -Rn '[inputs | select(length>0) | {(split(":")[0]): (sub("^[^:]*:"; ""))}] | add' \
                | gron | grep '"ipv6.dns"' | gron -v || true)

              if [[ -z "$IPv6_DNS_VPN" || "$IPv6_DNS_VPN" == "--" ]]; then
                IPv6_DNS_VPN=$(traceroute --interface=${cfg.vpnInterface} -n6 -m 1 google.com 2>/dev/null | tail -n1 | awk '{print $2}')
              fi

              if [[ "$IPv6_DNS_VPN" =~ : ]]; then
                echo "[update_nftables_v6] Valid IPv6 DNS endpoint detected: $IPv6_DNS_VPN"
                DNAT_RULES=$(cat <<RULES
                iifname "${cfg.lanInterface}" tcp dport 53 dnat to [${"$IPv6_DNS_VPN"}]:53
                iifname "${cfg.lanInterface}" udp dport 53 dnat to [${"$IPv6_DNS_VPN"}]:53
            RULES
            )
              else
                echo "[update_nftables_v6] No valid IPv6 DNS found (value: $IPv6_DNS_VPN). Skipping DNAT to avoid nft syntax errors."
                DNAT_RULES=""
              fi

              tmpfile=$(mktemp)
              cat >"$tmpfile" <<NFT
            table ip6 vpn {
              chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
            ${"$DNAT_RULES"}
              }

              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip6 saddr ${cfg.subnets.ipv6} oifname "${cfg.vpnInterface}" masquerade
              }

              chain mangle_forward {
                type filter hook forward priority mangle; policy accept;
                tcp flags syn tcp option maxseg size set rt mtu
              }

              chain forward {
                type filter hook forward priority 0; policy accept;
                iifname "${cfg.lanInterface}" oifname "${cfg.lanInterface}" accept
              }
            }
            NFT

              echo "[update_nftables_v6] nft ruleset preview:"
              cat "$tmpfile"
              nft -f "$tmpfile"
              rm -f "$tmpfile"

              echo "[update_nftables_v6] nftables IPv6 ruleset applied successfully"
          '';

        };
      };
      systemd.services.kea-dhcp4 = {
        description = "Kea DHCPv4 Server";
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        path = [
          pkgs.kea
          pkgs.systemd
          pkgs.gnugrep
        ];
        unitConfig = {
          StartLimitIntervalSec = 0;
        };

        serviceConfig = {
          ExecStart = pkgs.writeShellScript "kea-dhcp4-execstart" ''
            set -euo pipefail
            set -x

            mkdir -p /run/kea || true 
            mkdir -p /var/lib/kea || true
            chmod 0755 /run/kea

            exec kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
          '';

          Restart = "always";
          RestartSec = 20;
          ExecStartPost = pkgs.writeShellScript "kea-dhcp4-postcheck" ''
            set -euo pipefail
            set -x
            if ! journalctl -u kea-dhcp4 -b --since "$(systemctl show kea-dhcp4 -p InactiveEnterTimestamp --value)" | grep -v grep  | grep -q "listening on interface"; then
              echo "kea-dhcp4 not listening on any interface"
              exit 1
            fi

            sleep 3
            if journalctl -u kea-dhcp4 -b --since "$(systemctl show kea-dhcp4 -p InactiveEnterTimestamp --value)" | grep -v grep | grep -q "DHCPSRV_OPEN_SOCKET_FAIL"; then
              echo "kea-dhcp4 failed to open sockets"
              exit 1
            fi
          '';
        };

        preStart = ''
          set -euo pipefail
          set -x
          mkdir -p /etc/kea || true
          mkdir -p /var/lib/kea || true
          chmod 700 /var/lib/kea
          IPV4_ADDR="${cfg.subnets.ipv4}"

          NETWORK_INFO=$(${pkgs.sipcalc}/bin/sipcalc "''${IPV4_ADDR}")

          PREFIX=$(echo "''${NETWORK_INFO}" | ${pkgs.gawk}/bin/awk -F- '/Network address/ {gsub(/ /,"",$2); print $2}')
          CIDR=$(echo "''${IPV4_ADDR}" | cut -d/ -f2)
          NETMASK=$(echo "''${NETWORK_INFO}" | ${pkgs.gawk}/bin/awk -F- '/Network mask[[:space:]]*-/ {gsub(/ /,"",$2); print $2}')
          GATEWAY=$(echo "''${IPV4_ADDR}" | ${pkgs.gnused}/bin/sed 's#/.*##')

          FIRST_HOST=$(echo "''${NETWORK_INFO}" | ${pkgs.gawk}/bin/awk '/Usable range/ {print $4}')
          LAST_HOST=$(echo "''${NETWORK_INFO}" | ${pkgs.gawk}/bin/awk '/Usable range/ {print $6}')
          POOL="''${FIRST_HOST}-''${LAST_HOST}"

          mkdir -p /etc/kea
          cat > /etc/kea/kea-dhcp4.conf <<EOF
          {
            "Dhcp4": {
              "valid-lifetime": 600,
              "renew-timer": 300,
              "rebind-timer": 540,
              "interfaces-config": {
                "interfaces": [ "${cfg.lanInterface}" ]
              },
              "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": "/var/lib/kea/dhcp4.leases"
              },
              "subnet4": [
                {
                  "id": 1,
                  "subnet": "''${PREFIX}/''${CIDR}",
                  "pools": [
                    { "pool": "''${POOL}" }
                  ],
                  "option-data": [
                    { "name": "routers", "data": "''${GATEWAY}" },
                    { "name": "subnet-mask", "data": "''${NETMASK}" },
                    { "name": "domain-name-servers", "data": "''${GATEWAY}" }
                  ]
                }
              ]
            }
          }
          EOF
        '';
      };

      systemd.services.radvd = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        path = [ pkgs.radvd ];

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

          IPV6_ADDR=$(${pkgs.iproute2}/bin/ip -6 a s ${cfg.lanInterface} | grep 'scope global' | ${pkgs.gawk}/bin/awk '{print $2}')

          IPV6_ADDR=${cfg.subnets.ipv6}

          PREFIX=$(${pkgs.sipcalc}/bin/sipcalc "$IPV6_ADDR")
          PREFIX=$(${pkgs.sipcalc}/bin/sipcalc "$IPV6_ADDR" | grep 'Subnet prefix' | ${pkgs.gawk}/bin/awk '{print $5}')
          IPV6_ADDR_WITHOUT_MASK=$(echo $IPV6_ADDR | sed 's/\/.*//g')
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
