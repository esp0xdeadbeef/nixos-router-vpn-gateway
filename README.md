# nixos-router-vpn-gateway
A NixOS module for building a router with VPN gateway support (WireGuard/OpenVPN). Provides IPv4/IPv6 NAT, DHCPv4 (kea), RA (radvd), and routes IPv6 traffic via the WireGuard /128 endpoint.



# usage in container:

```
{ config, pkgs, lib, inputs, ... }:

{
  containers.lan-to-vpn-1 = {
    autoStart = true;
    privateNetwork = true;

    extraVeths = {
      wan.hostBridge = "br-wan";
      lan.hostBridge = "br-lan";
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
        vpnInterface = "tun0";
        vpnProfile = "/etc/vpn/tun0.conf";
        subnets.ipv4 = "10.10.10.1/24";
        subnets.ipv6 = "fd10:dead:beef::1/64";
        dhcp4.enable = true;
        ra.enable = true;
      };
    };
  };
}
```
