# nixos-router-vpn-gateway
A NixOS module for building a router with VPN gateway support (WireGuard/OpenVPN). Provides IPv4/IPv6 NAT, DHCPv4 (kea), RA (radvd), and routes IPv6 traffic via the WireGuard /128 endpoint.



# usage in container:

```nix
{
  config,
  pkgs,
  lib,
  inputs,
  ...
}:

let
  management_interface = "ens18";
  upstream_VPN_interface = "ens19";
  vpnNATInterface = "ens20";

  vpnInterface = "tun0";
  vpnConfBasePath = "/etc/vpn";
  vpnConfPath = "${vpnConfBasePath}/${vpnInterface}.conf";
  vpnIPv4WithMask = "10.90.0.1/24";
  vpnIPv6WithMask = "fd90:dead:beef::100/64";

  # ignore this
  vrf_table_vpn = 10;
  vrf_name_vpn = "vrf-vpn";

in
{

  boot.kernel.sysctl = {
    "net.ipv6.conf.br-ens19.accept_ra" = 0;
    "net.ipv6.conf.br-ens20.accept_ra" = 0;
  };

  networking.bridges.br-ens19.interfaces = [ "ens19" ];
  networking.bridges.br-ens20.interfaces = [ "ens20" ];

  systemd.network.networks."br-ens20" = {
    matchConfig.Name = "br-ens20";
    linkConfig.RequiredForOnline = "no";
    networkConfig.DHCP = "no";
    networkConfig.IPv6AcceptRA = false;
  };

  systemd.network.networks."br-ens19" = {
    matchConfig.Name = "br-ens19";
    linkConfig.RequiredForOnline = "no";
    networkConfig.DHCP = "no";
    networkConfig.IPv6AcceptRA = false;
  };

  # networking.vlans."ens19.3" = { id = 3; interface = "ens19"; };
  # networking.bridges.br-ens19.interfaces = [ "ens19.3" ];

  systemd.services."container@lan-to-vpn-<replaced-vpn-provider-name>".serviceConfig.ConditionPathExists = vpnConfPath;

  containers.lan-to-vpn-<replaced-vpn-provider-name> = {
    autoStart = true;
    privateNetwork = true;

    extraVeths = {
      wan.hostBridge = "br-ens19";
      lan.hostBridge = "br-ens20";
    };

    bindMounts."/etc/vpn" = {
      hostPath = "/etc/vpn";
      isReadOnly = true;
    };

    config = { pkgs, config, ... }: {
      imports = [ inputs.nixos-router-vpn-gateway.nixosModules.default ];

      services.router-vpn-gateway = {
        enable = true;
        wanInterface = "wan";
        lanInterface = "lan";
        vpnInterface = vpnInterface;
        vpnProfile = vpnConfPath;
        subnets.ipv4 = vpnIPv4WithMask;
        subnets.ipv6 = vpnIPv6WithMask;
        dhcp4.enable = true;
        ra.enable = true;
      };
    };

  };

  sops.secrets."vpn-configuration" = {
    owner = "root";
    group = "root";
    mode = "0400";
  };

  systemd.services.write-vpn-config = {
    description = "Decode VPN config from sops and write to ${vpnConfPath}";
    wantedBy = [ "network-pre.target" ];
    before = [ "network-online.target" ];
    after = [ "local-fs.target" ];

    serviceConfig = {
      Type = "oneshot";
      ExecStart = pkgs.writeShellScript "write-vpn-config" ''
        set -euxo pipefail
        mkdir -p ${vpnConfBasePath}
        secret_path="${config.sops.secrets."vpn-configuration".path}"
        if [ -f "$secret_path" ] && [ -s "$secret_path" ]; then
        cat "$secret_path" | ${pkgs.coreutils}/bin/base64 -d > ${vpnConfPath}
        chmod 600 ${vpnConfPath}
        else
        echo "[ERROR] VPN config secret missing or empty: $secret_path" >&2
        exit 1
        fi
      '';
    };
  };
}


```
