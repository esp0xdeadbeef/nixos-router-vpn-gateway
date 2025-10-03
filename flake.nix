{
  description = "Reusable VPN gateway module (WireGuard/OpenVPN + NAT, DHCP, RA)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs, ... }: {
    nixosModules.default = import ./modules/vpn-gateway.nix;
  };
}

