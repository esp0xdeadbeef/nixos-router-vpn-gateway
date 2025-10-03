{ lib, pkgs, config, ... }:

with lib;

let
  cfg = config.services.router-vpn-gateway;
in {
  options.services.router-vpn-gateway = {
    enable = mkEnableOption "Enable the VPN router container";

    wanInterface = mkOption {
      type = types.str;
      example = "wan";
      description = "Upstream interface inside the container";
    };

    lanInterface = mkOption {
      type = types.str;
      example = "lan";
      description = "Downstream interface inside the container";
    };

    vpnInterface = mkOption {
      type = types.str;
      default = "tun0";
      description = "Tunnel interface (WireGuard/OpenVPN)";
    };

    vpnProfile = mkOption {
      type = types.path;
      description = "Path to VPN profile config file (wg or ovpn). Usually bind-mounted.";
    };

    subnets.ipv4 = mkOption {
      type = types.str;
      example = "10.90.0.1/24";
    };

    subnets.ipv6 = mkOption {
      type = types.str;
      example = "fd90:dead:beef::100/64";
    };

    dhcp4.enable = mkEnableOption "Enable Kea DHCPv4 server";
    ra.enable = mkEnableOption "Enable radvd Router Advertisements for IPv6";
  };

  config = mkIf cfg.enable {
    system.stateVersion = "25.05";

    boot.kernelModules = [ "ip6table_nat" "vrf" ];
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    # =============== VPN dispatcher ====================
    systemd.targets.vpn-ready = {
      description = "VPN interface ready";
      wantedBy = [ "multi-user.target" ];
    };

    systemd.services.vpn-dispatcher = {
      description = "Bring up VPN tunnel (${cfg.vpnInterface})";
      after = [ "systemd-networkd.service" ];
      wantedBy = [ "multi-user.target" ];
      path = with pkgs; [ iproute2 wireguard-tools openvpn systemd ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "vpn-dispatcher" ''
          set -euxo pipefail
          CONF=${cfg.vpnProfile}
          if grep -qE '^\[Interface\]' "$CONF"; then
            ${pkgs.wireguard-tools}/bin/wg-quick up "$CONF"
          elif grep -qE '^(client|dev|proto|remote)' "$CONF"; then
            ${pkgs.openvpn}/bin/openvpn --config "$CONF" --daemon
            sleep 2
          else
            echo "[!] Unknown VPN config format"
            exit 1
          fi
          systemctl start vpn-ready.target
        '';
        ExecStop = pkgs.writeShellScript "vpn-dispatcher-stop" ''
          CONF=${cfg.vpnProfile}
          if grep -qE '^\[Interface\]' "$CONF"; then
            ${pkgs.wireguard-tools}/bin/wg-quick down "$CONF" || true
          else
            pkill -f "openvpn --config $CONF" || true
          fi
        '';
      };
    };

    # =============== NAT ====================
    systemd.services.vpn-nat = {
      after = [ "vpn-ready.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.iptables ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "vpn-nat" ''
          # IPv4 masquerade
          ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s ${cfg.subnets.ipv4} -o ${cfg.vpnInterface} -j MASQUERADE
          # IPv6 masquerade (/128 tunnel NAT)
          ${pkgs.ip6tables}/bin/ip6tables -t nat -A POSTROUTING -s ${cfg.subnets.ipv6} -o ${cfg.vpnInterface} -j MASQUERADE
        '';
      };
    };

    # =============== DHCPv4 ====================
    systemd.services.kea-dhcp4 = mkIf cfg.dhcp4.enable {
      description = "Kea DHCPv4 server";
      after = [ "vpn-ready.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.kea ];
      serviceConfig = {
        ExecStart = pkgs.writeShellScript "kea-dhcp4" ''
          mkdir -p /etc/kea /var/lib/kea
          cat > /etc/kea/kea-dhcp4.conf <<EOF
          {
            "Dhcp4": {
              "valid-lifetime": 600,
              "interfaces-config": { "interfaces": [ "${cfg.lanInterface}" ] },
              "lease-database": { "type": "memfile", "name": "/var/lib/kea/dhcp4.leases" },
              "subnet4": [ { "subnet": "${cfg.subnets.ipv4}", "pools": [ { "pool": "${cfg.subnets.ipv4}" } ] } ]
            }
          }
          EOF
          ${pkgs.kea}/bin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf
        '';
      };
    };

    # =============== Router Advertisements ====================
    systemd.services.radvd = mkIf cfg.ra.enable {
      description = "IPv6 RA daemon";
      after = [ "vpn-ready.target" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.radvd pkgs.sipcalc ];
      serviceConfig = {
        ExecStart = "${pkgs.radvd}/bin/radvd -C /etc/radvd.conf -n";
      };
      preStart = ''
        PREFIX=$(${pkgs.sipcalc}/bin/sipcalc ${cfg.subnets.ipv6} | grep "Subnet prefix" | awk '{print $5}')
        ADDR=$(echo ${cfg.subnets.ipv6} | cut -d/ -f1)
        cat > /etc/radvd.conf <<EOF
        interface ${cfg.lanInterface} {
          AdvSendAdvert on;
          RDNSS $ADDR {};
          prefix $PREFIX {
            AdvOnLink on;
            AdvAutonomous on;
          };
        };
        EOF
      '';
    };
  };
}

