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

    # Use str because this is a runtime path in the container (not a Nix store path)
    vpnProfile = mkOption {
      type = types.str;
      description = "Path to WireGuard/OpenVPN config file (e.g., /etc/vpn/tun0.conf)";
    };

    subnets = {
      ipv4 = mkOption {
        type = types.str; # "10.90.0.1/24"
        example = "10.90.0.1/24";
      };
      ipv6 = mkOption {
        type = types.str; # "fd90:dead:beef::100/64"
        example = "fd90:dead:beef::100/64";
      };
    };

    dhcp4.enable = mkEnableOption "Enable DHCPv4";
    ra.enable = mkEnableOption "Enable IPv6 Router Advertisements";
  };

  config = mkIf cfg.enable (
    let
      # derive your “constants” from options
      split4 = lib.splitString "/" cfg.subnets.ipv4;
      vpnIPv4Address = builtins.elemAt split4 0;
      vpnIPv4Mask = builtins.elemAt split4 1;

      split6 = lib.splitString "/" cfg.subnets.ipv6;
      vpnIPv6Address = builtins.elemAt split6 0;
      vpnIPv6Mask = builtins.elemAt split6 1;

      vpnIPv4WithMask = cfg.subnets.ipv4;
      vpnIPv6WithMask = cfg.subnets.ipv6;

      wanIface = cfg.wanInterface;
      lanIface = cfg.lanInterface;
      vpnIface = cfg.vpnInterface;

      vpnNATInterface = cfg.lanInterface;
      vpnInterface = cfg.vpnInterface;

      vpnConfBasePath = "/etc/vpn";
      vpnConfPath = "${vpnConfBasePath}/${vpnIface}.conf";

      enableVRF = false;
    in
    {
      networking.useHostResolvConf = lib.mkForce false;
      services.resolved.enable = true;
      networking.useDHCP = lib.mkDefault false;
      networking.interfaces.wan.useDHCP = true;

      networking.interfaces.lan = {
        ipv4.addresses = [
          {
            address = vpnIPv4Address;
            prefixLength = 24;
          }
        ];

        ipv6 = {
          addresses = [
            {
              address = vpnIPv6Address;
              prefixLength = 64;
            }
          ];
        };
      };

      networking.networkmanager.enable = false;

      boot.kernelModules = [
        "vrf"
        "ip6table_nat"
      ];
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv4.tcp_l3mdev_accept" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
      };

      # 2. Systemd target that signals when VPN is ready
      systemd.targets.vpn-ready = {
        description = "VPN interface is up and ready";
        wantedBy = [ "multi-user.target" ];
      };

      # 3. Decode VPN config at boot
      systemd.services.write-vpn-config = {
        description = "Decode VPN config from sops and write to ${vpnConfPath}";
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
        description = "Bring up VPN tunnel (${vpnInterface}) and signal vpn-ready.target";
        after = [
          "write-vpn-config.service"
          "systemd-networkd.service"
        ];
        requires = [
          "write-vpn-config.service"
          "systemd-networkd.service"
        ];
        wantedBy = [ "multi-user.target" ];

        path = with pkgs; [
          iproute2
          coreutils
          gawk
          wireguard-tools
          openvpn
          systemd
          nftables
        ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true; # keeps it “active” once setup succeeds
          Restart = "on-failure"; # rerun if setup fails
          RestartSec = 10;

          ExecStart = pkgs.writeShellScript "vpn-dispatcher-start" ''
            set -euxo pipefail
            CONF=${vpnConfPath}

            if grep -qE '^\[Interface\]' "$CONF"; then
              echo "[+] Detected WireGuard config"
              ${pkgs.wireguard-tools}/bin/wg-quick up "$CONF"
            elif grep -qE '^(client|dev|proto|remote)' "$CONF"; then
              echo "[+] Detected OpenVPN config"
              ${pkgs.openvpn}/bin/openvpn --config "$CONF" --daemon
              sleep 2
            else
              echo "[!] Unknown VPN config format"
              exit 1
            fi

            # confirm interface exists
            if ! ip link show "${vpnInterface}" > /dev/null 2>&1; then
              echo "[!] ${vpnInterface} not present after bringup"
              exit 1
            fi

            # fire vpn-ready only once
            if [ ! -e /run/vpn-ready.once ]; then
              systemctl start vpn-ready.target
              touch /run/vpn-ready.once
            fi
          '';

          ExecStop = pkgs.writeShellScript "vpn-dispatcher-stop" ''
            set -euxo pipefail
            CONF=${vpnConfPath}
            if grep -qE '^\[Interface\]' "$CONF"; then
              ${pkgs.wireguard-tools}/bin/wg-quick down "$CONF" || true
            elif grep -qE '^(client|dev|proto|remote)' "$CONF"; then
              pkill -f "openvpn --config $CONF" || true
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
            iface="${vpnInterface}"
            rx_path="/sys/class/net/$iface/statistics/rx_bytes"

            # 1. Interface must exist
            if [[ ! -d "/sys/class/net/$iface" ]]; then
              echo "[vpn-check] $iface missing -> restarting vpn-dispatcher"
              systemctl restart vpn-dispatcher.service
              exit 0
            fi

            # 2. RX counter must be readable
            if [[ ! -r "$rx_path" ]]; then
              echo "[vpn-check] Cannot read $rx_path -> restarting vpn-dispatcher"
              systemctl restart vpn-dispatcher.service
              exit 0
            fi

            RX_BEFORE=$(cat "$rx_path")
            sleep 5   # short sampling window
            RX_AFTER=$(cat "$rx_path")

            # 3. If no RX change, fallback to ping
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
          OnUnitActiveSec = "60s"; # check every 60s
          AccuracySec = "5s";
          Unit = "vpn-check.service";
        };
      };

      # 5. Example dependent service
      systemd.services.portforwards = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        serviceConfig = {
          ExecStart = pkgs.writeShellScript "portforwards-bin" ''
            set -euo pipefail
            set -x

            # Load subnet info (should set ${vpnIPv4WithMask} and ${vpnIPv6WithMask})
            . /etc/root/subnets.sh

            # Extract prefixes from /CIDR notation
            IPV6_PREFIX=$(echo "${vpnIPv6WithMask}" | cut -d/ -f1 | cut -d: -f1-3):
            IPV4_PREFIX=$(echo "${vpnIPv4WithMask}" | cut -d/ -f1 | cut -d. -f1-3)

            # Format: [source_port]="last_octet:destination_port"
            declare -A HOSTS_IPV4=(
              [21612]="109:22"
              [21613]="167:80"
              [21614]="163:443"
            )

            # Format: [source_port]=":ipv6_suffix]:destination_port"
            declare -A HOSTS_IPV6=(
              [21612]=":a28f:aa25:f510:bdcb]:22"
              [21613]=":be24:11ff:fe3d:474d]:80"
              [21614]=":a133:c085:eeab:f2c1]:443"
            )

            for port in "''${!HOSTS_IPV4[@]}"; do
              # ----- IPv4 Parsing -----
              IFS=':' read -r ipv4_host dst_port_v4 <<< "''${HOSTS_IPV4[$port]}"
              dst_port_v4="''${dst_port_v4:-$port}"

              # ----- IPv6 Parsing -----
              raw_ipv6_entry="''${HOSTS_IPV6[$port]}"
              dst_port_v6="''${raw_ipv6_entry##*:}"                    # after last :
              ipv6_host_suffix="''${raw_ipv6_entry%]:$dst_port_v6}"    # remove ]:<port>
              ipv6_host_suffix="''${ipv6_host_suffix#:}"              # strip leading :

              # ----- Rules -----

              # IPv4 rule
              ${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -i ${vpnInterface} -p tcp --dport "$port" \
                -j DNAT --to-destination "$IPV4_PREFIX.$ipv4_host:$dst_port_v4"

              # IPv6 rule
              ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${vpnInterface} -p tcp --dport "$port" \
                -j DNAT --to-destination "[$IPV6_PREFIX:$ipv6_host_suffix]:$dst_port_v6"
            done
          '';
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
        };
      };

      systemd.services.update_iptables_v4 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        path = [ pkgs.networkmanager ];
        serviceConfig = {
          ExecStart = pkgs.writeShellScript "update_iptables_v4" ''
            set -euo pipefail
            set -x
            # Get the current IP address of ${vpnInterface}
            source /etc/root/subnets.sh

            # IPv4_DNS_VPN=$(${pkgs.networkmanager}/bin/nmcli connection show ${vpnInterface} | grep 'ipv4.dns' | ${pkgs.gawk}/bin/awk '{print $2}' | head -n1)
            # IPv4_DNS_VPN=$(${pkgs.systemd}/bin/resolvectl dns "${vpnInterface}"  | cut -d ':' -f 2 | ${pkgs.util-linux}/bin/rev | ${pkgs.gawk}/bin/awk '{print $2; exit}' | ${pkgs.util-linux}/bin/rev)
            IPv4_DNS_VPN=$(${pkgs.systemd}/bin/resolvectl dns "${vpnInterface}" | ${pkgs.util-linux}/bin/rev | ${pkgs.gawk}/bin/awk '{print $2; exit}' | ${pkgs.util-linux}/bin/rev)
            if [[ -z "$IPv4_DNS_VPN" || "$IPv4_DNS_VPN" == "--" ]]; then
                # If it's empty or has '--', get the first hop's IPv4 address from traceroute and assign it to IPv4_DNS_VPN
                IPv4_DNS_VPN=$(${pkgs.traceroute}/bin/traceroute --interface=${vpnInterface} -n4 -m 1 google.com | tail -n1 | ${pkgs.gawk}/bin/awk '{print $2}')
                echo "IPV4 Tunnel IP: $IPv4_DNS_VPN"
            fi

            # logging for DNS:
            echo "IPv4_DNS_VPN: $IPv4_DNS_VPN"

            # Flush old rules for port 53 forwarding
            ${pkgs.iptables}/bin/iptables -t nat -D PREROUTING -i ${vpnNATInterface} -p udp --dport 53 -j DNAT --to-destination $IPv4_DNS_VPN || true
            ${pkgs.iptables}/bin/iptables -t nat -D PREROUTING -i ${vpnNATInterface} -p tcp --dport 53 -j DNAT --to-destination $IPv4_DNS_VPN || true
            # Allow forwarding to self
            ${pkgs.iptables}/bin/iptables -I FORWARD -i ${vpnNATInterface} -o ${vpnNATInterface} -j ACCEPT
            # Portforwards DNS
            ${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -i ${vpnNATInterface} -p udp --dport 53 -j DNAT --to-destination $IPv4_DNS_VPN
            ${pkgs.iptables}/bin/iptables -t nat -A PREROUTING -i ${vpnNATInterface} -p tcp --dport 53 -j DNAT --to-destination $IPv4_DNS_VPN
            # MASQUERADE the traffic from ${vpnIPv4WithMask} to ${vpnInterface}
            ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s ${vpnIPv4WithMask} -o ${vpnInterface} -j MASQUERADE
            # MSS clamping (mtu size forcing) 
            ${pkgs.iptables}/bin/iptables -t mangle -A FORWARD -o ${vpnInterface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu


          '';
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
        };
      };
      systemd.services.update_iptables_v6 = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "vpn-ready.target" ];
        after = [ "vpn-ready.target" ];
        path = [ pkgs.networkmanager ];
        serviceConfig = {
          ExecStart = pkgs.writeShellScript "update_iptables_v6" ''
            set -euo pipefail
            set -x
            # Get the current IP address of ${vpnInterface}
            source /etc/root/subnets.sh

            # IPv6_DNS_VPN=$(${pkgs.networkmanager}/bin/nmcli connection show ${vpnInterface} | grep 'ipv6.dns' | ${pkgs.gawk}/bin/awk '{print $2}' | head -n1)
            IPv6_DNS_VPN=$(${pkgs.systemd}/bin/resolvectl dns "${vpnInterface}" | ${pkgs.util-linux}/bin/rev | ${pkgs.gawk}/bin/awk '{print $1; exit}' | ${pkgs.util-linux}/bin/rev)

            IPv6_INTERFACE_NATTED_LAN=$(${pkgs.iproute2}/bin/ip -6 a s ${vpnNATInterface} | grep 'scope global' | ${pkgs.gawk}/bin/awk '{print $2}' | cut -d '/' -f 1)
            IPv6_INTERFACE_NATTED_LAN_WITH_SUBNET=$(${pkgs.iproute2}/bin/ip -6 a s ${vpnNATInterface} | grep 'scope global' | ${pkgs.gawk}/bin/awk '{print $2}')


            # Check if the DNS setting is empty or if it contains '--'
            if [[ -z "$IPv6_DNS_VPN" || "$IPv6_DNS_VPN" == "--" ]]; then
                # If it's empty or has '--', get the first hop's IPv6 address from traceroute and assign it to IPv6_DNS_VPN
                IPv6_DNS_VPN=$(${pkgs.traceroute}/bin/traceroute --interface=${vpnInterface} -n6 -m 1 google.com | tail -n1 | ${pkgs.gawk}/bin/awk '{print $2}')
                echo "IPV6 Tunnel IP: $IPv6_DNS_VPN"
            fi

            # logging for DNS:
            echo "IPv6_DNS_VPN: $IPv6_DNS_VPN"



            # Flush old rules for port 53 forwarding
            ${pkgs.iptables}/bin/ip6tables -t nat -D PREROUTING -i ${vpnNATInterface} -p udp --dport 53 -j DNAT --to-destination $IPv6_DNS_VPN || true
            ${pkgs.iptables}/bin/ip6tables -t nat -D PREROUTING -i ${vpnNATInterface} -p tcp --dport 53 -j DNAT --to-destination $IPv6_DNS_VPN || true

            # allow callbacks on the adapter itself
            ${pkgs.iptables}/bin/ip6tables -I FORWARD -i ${vpnNATInterface} -o ${vpnNATInterface} -j ACCEPT
            # Add new rules with the current IP address
            ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${vpnNATInterface} -p udp --dport 53 -j DNAT --to-destination $IPv6_DNS_VPN
            ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${vpnNATInterface} -p tcp --dport 53 -j DNAT --to-destination $IPv6_DNS_VPN

            # DNAT any incoming UDP or TCP DNS on ${vpnNATInterface} to the real VPN DNS server
            ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${vpnNATInterface} -p udp --dport 53 -d $IPv6_INTERFACE_NATTED_LAN -j DNAT --to-destination "[$IPv6_DNS_VPN]:53"
            ${pkgs.iptables}/bin/ip6tables -t nat -A PREROUTING -i ${vpnNATInterface} -p tcp --dport 53 -d $IPv6_INTERFACE_NATTED_LAN -j DNAT --to-destination "[$IPv6_DNS_VPN]:53"
            ${pkgs.iptables}/bin/ip6tables -A FORWARD -i ${vpnNATInterface} -o ${vpnInterface} -p udp --dport 53 -d $IPv6_DNS_VPN -j ACCEPT
            ${pkgs.iptables}/bin/ip6tables -A FORWARD -i ${vpnNATInterface} -o ${vpnInterface} -p tcp --dport 53 -d $IPv6_DNS_VPN -j ACCEPT

            # All traffic from LAN to VPN
            ${pkgs.iptables}/bin/ip6tables -A FORWARD -i ${vpnNATInterface} -o ${vpnInterface} -s $IPv6_INTERFACE_NATTED_LAN_WITH_SUBNET -j ACCEPT

            # Return traffic
            ${pkgs.iptables}/bin/ip6tables -A FORWARD -i ${vpnInterface} -o ${vpnNATInterface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

            # Accept return traffic
            ${pkgs.iptables}/bin/ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
            ${pkgs.iptables}/bin/ip6tables -t nat -A POSTROUTING -s $IPv6_INTERFACE_NATTED_LAN_WITH_SUBNET -o ${vpnInterface} -j MASQUERADE


            ${pkgs.iptables}/bin/ip6tables -t mangle -A FORWARD -o ${vpnInterface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
          '';
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 10;
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
        ];
        unitConfig = {
          StartLimitIntervalSec = 0; # disables rate limiting
        };

        serviceConfig = {
          ExecStart = pkgs.writeShellScript "kea-dhcp4-execstart" ''
            set -euo pipefail
            set -x
            mkdir -p /var/run/kea || true
            ${pkgs.kea}/bin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
          '';

          Type = "simple";
          Restart = "always"; # keep restarting no matter what
          RestartSec = 1; # 1s between attempts
          # your ExecStart, ExecStartPost, etc...
          ExecStartPost = pkgs.writeShellScript "kea-dhcp4-postcheck" ''
            set -euo pipefail


            # we should have a different way of checking if dhcp4 is working, this still sucks:

            LOG="$(${pkgs.systemd}/bin/journalctl -u kea-dhcp4 | tail -n 40)"

            if ! echo "$LOG" | ${pkgs.gnugrep}/bin/grep -q "listening on interface"; then
              echo "kea-dhcp4 not listening on any interface"
              exit 1
            fi

            sleep 3
            LOG="$(${pkgs.systemd}/bin/journalctl -u kea-dhcp4 -n 40)"
            if echo "$LOG" | ${pkgs.gnugrep}/bin/grep -q "DHCPSRV_OPEN_SOCKET_FAIL"; then
              echo "kea-dhcp4 failed to open sockets"
              exit 1
            fi

          '';

          # This ensures /run/kea/ exists with proper perms
          RuntimeDirectory = "kea";
          RuntimeDirectoryMode = "0755";
        };

        preStart = ''
          set -euo pipefail
          set -x
          mkdir -p /etc/kea || true
          mkdir -p /var/lib/kea || true
          chmod 700 /var/lib/kea
          source /etc/root/subnets.sh
          IPV4_ADDR="${vpnIPv4WithMask}"

          # Get network details from sipcalc
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
                "interfaces": [ "${vpnNATInterface}" ]
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
          ExecStart = "${pkgs.radvd}/bin/radvd -n -C /etc/radvd.conf ${vpnNATInterface}";
          Restart = "on-failure";
          RestartSec = 10;
          # StartLimitIntervalSec = 0;
          StartLimitBurst = 0;
        };

        preStart = ''
          echo "Generating radvd.conf..."
          set -euo pipefail
          set -x

          # Extract IPv6 address and subnet prefix for ${vpnNATInterface}
          IPV6_ADDR=$(${pkgs.iproute2}/bin/ip -6 a s ${vpnNATInterface} | grep 'scope global' | ${pkgs.gawk}/bin/awk '{print $2}')

          source /etc/root/subnets.sh
          IPV6_ADDR=${vpnIPv6WithMask}

          PREFIX=$(${pkgs.sipcalc}/bin/sipcalc "$IPV6_ADDR")
          PREFIX=$(${pkgs.sipcalc}/bin/sipcalc "$IPV6_ADDR" | grep 'Subnet prefix' | ${pkgs.gawk}/bin/awk '{print $5}')
          IPV6_ADDR_WITHOUT_MASK=$(echo $IPV6_ADDR | sed 's/\/.*//g')
          echo -n 'interface ${vpnNATInterface} {
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

      # environment.systemPackages = with pkgs; [
      #   # coreutils
      #   # python3
      #   # coreutils
      #   dnsutils # dig
      #   openvpn
      #   wireguard-tools
      #   tcpdump
      #   traceroute
      #   nftables
      # ];

      environment.etc = {
        "root/subnets.sh" = {
          source = pkgs.writeShellScript "subnets" ''
            export IPV4_VPN_SUBNET_STATIC_WITH_MASK="${vpnIPv4WithMask}"
            export IPV6_VPN_SUBNET_STATIC_WITH_MASK="${vpnIPv6WithMask}"
          '';
          mode = "0755";
        };

        # "root/restore_internet.sh" = {
        #   source = pkgs.writeShellScript "restore_internet" ''
        #     #!/usr/bin/env bash
        #     sudo systemctl stop vpn-dispatcher.service
        #     set -euxo pipefail

        #     NUKE_IFACES=("tun0" "ens19" "ens20")

        #     echo "[+] Killing routes and rules for: ''${NUKE_IFACES[*]}"

        #     for IFACE in "''${NUKE_IFACES[@]}"; do
        #       echo "[-] Nuking interface: $IFACE"

        #       # Flush routes from other tables that use the interface
        #       for TABLE in $(ip route show table all | grep -F "$IFACE" | awk '{print $NF}' | sort -u); do
        #         echo "  -> Flushing routes from table $TABLE"
        #         ip route flush table "$TABLE" dev "$IFACE" || true
        #         ip -6 route flush table "$TABLE" dev "$IFACE" || true
        #       done

        #       # Delete rules that reference the interface
        #       ip rule | grep "$IFACE" || true
        #       for RULE in $(ip rule | grep "$IFACE" | awk '{print $1}'); do
        #         echo "  -> Deleting ip rule $RULE"
        #         ip rule del priority "$RULE" || true
        #       done

        #       # Detach from VRF if necessary
        #       if [ -e "/sys/class/net/$IFACE/master" ]; then
        #         echo "  -> Detaching $IFACE from VRF"
        #         ip link set dev "$IFACE" nomaster || true
        #       fi

        #       # Bring interface down
        #       ip link set dev "$IFACE" down || true
        #     done

        #     echo "[+] Flushing iptables and ip6tables for cleanup"
        #     iptables -F
        #     iptables -t nat -F
        #     iptables -t mangle -F
        #     ip6tables -F
        #     ip6tables -t nat -F
        #     ip6tables -t mangle -F

        #     sudo ip link set dev ens18 up
        #     nft delete table inet vpnblock || true
        #     echo "[+] Done. VRF interfaces nuked. Main interface untouched."
        #     ip a show dev ens18
        #     ip r

        #     echo "[+] Setting fallback DNS to 1.1.1.1 and 9.9.9.9"
        #     echo -e "nameserver 1.1.1.1\nnameserver 9.9.9.9" > /etc/resolv.conf

        #     echo "[+] Final IP state on management interface:"
        #     ip a show dev ens18

        #     echo "[+] Route table:"
        #     ip r

        #     echo "[+] Testing external connectivity:"
        #     ping -c 2 1.1.1.1
        #     curl -s https://ifconfig.me || echo "curl failed"

        #     echo "[✓] VRF interfaces nuked. DNS + routing restored via ens18."

        #   '';
        #   mode = "0755";
        # };

        # "NetworkManager/system-connections/${management_interface}.nmconnection" = {
        #   text = ''
        #     [connection]
        #     id=${management_interface}
        #     type=ethernet
        #     interface-name=${management_interface}
        #     autoconnect=true
        #     permissions=

        #     [ipv4]
        #     method=auto
        #     route-metric=300
        #     ${if enableVRF then "" else "ignore-auto-dns=true\nnever-default=true"}

        #     [ipv6]
        #     method=auto
        #     route-metric=300
        #     ${if enableVRF then "" else "ignore-auto-dns=true\nnever-default=true"}
        #   '';
        #   mode = "0600";
        # };

        # "NetworkManager/system-connections/${upstream_VPN_interface}.nmconnection" = lib.mkIf (!enableVRF) {
        #   text = ''
        #     [connection]
        #     id=${upstream_VPN_interface}
        #     type=ethernet
        #     interface-name=${upstream_VPN_interface}
        #     autoconnect=true
        #     permissions=

        #     [ipv4]
        #     method=auto
        #     route-metric=500
        #     ignore-auto-dns=false

        #     [ipv6]
        #     method=auto
        #     route-metric=100
        #     ignore-auto-dns=false
        #   '';
        #   mode = "0600";
        # };

        # "NetworkManager/system-connections/${vpnNATInterface}.nmconnection" = lib.mkIf (!enableVRF) {
        #   text = ''
        #     [connection]
        #     id=${vpnNATInterface}
        #     type=ethernet
        #     interface-name=${vpnNATInterface}
        #     autoconnect=true
        #     permissions=

        #     [ipv4]
        #     method=manual
        #     address1=${vpnIPv4WithMask}
        #     route-metric=1000
        #     ignore-auto-dns=true
        #     never-default=true

        #     [ipv6]
        #     method=manual
        #     address1=${vpnIPv6WithMask}
        #     route-metric=1000
        #     ignore-auto-dns=true
        #     never-default=true
        #   '';
        #   mode = "0600";
        # };
      };

      networking.useNetworkd = true;

      # Disable networkd-wait-online
      systemd.services.systemd-networkd-wait-online.enable = pkgs.lib.mkForce false;

      environment.systemPackages = with pkgs; [
        dnsutils
        openvpn
        wireguard-tools
        tcpdump
        traceroute
        nftables
        dhcpcd
        tmux
      ];
    }
  );
}
