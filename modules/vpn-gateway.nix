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

      vpnConfBasePath = "/etc/vpn";
      vpnConfPath = "${vpnConfBasePath}/${vpnIface}.conf";

      enableVRF = false;
    in
    {
      system.stateVersion = "25.05";

      # dummy service just to prove the module evaluates
      systemd.services.helloworld = {
        description = "Simple Hello World service";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.coreutils}/bin/echo Hello world";
        };
      };
    }
  );
}
