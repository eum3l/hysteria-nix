# hysteria-nix
> Nix Package and NixOS Module ([Options](OPTIONS.md)) for [Hysteria](https://v2.hysteria.network/)

```sh
nix run github:eum3l/hysteria-nix
```

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    hysteria.url = "github:eum3l/hysteria-nix";
  };

  outputs = {
    hysteria,
    nixpkgs,
    ...
  }: {
    nixosConfigurations.default = let 
      system = "x86_64-linux";
    in nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        hysteria.nixosModules.default
        {
          # Module
          services.hysteria.enable = true;
          
          # Package
          environment.systemPackages = [
            hysteria.packages.${system}.default
          ];
        
          # Cache
          nix.settings = {
            trusted-public-keys = [
              "hysteria.cachix.org-1:zAG2qV/akrj0TPOf28gxWTDj57f8SuYjqjHw2u38vZI="
            ];
            substituters = [
              "https://hysteria.cachix.org" 
            ];
          };
        }
      ];
    };
  };
}
```
