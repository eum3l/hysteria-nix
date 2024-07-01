rec {
  description = "Hysteria is a powerful, lightning fast and censorship resistant proxy.";

  nixConfig = {
    extra-substituters = [ "https://hysteria.cachix.org" ];
    extra-trusted-public-keys = [
      "hysteria.cachix.org-1:zAG2qV/akrj0TPOf28gxWTDj57f8SuYjqjHw2u38vZI="
    ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    options-nix.url = "github:eum3l/options.nix";
    src = {
      type = "github";
      owner = "apernet";
      repo = "hysteria";
      ref = "app/v2.5.0";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      src,
      options-nix,
    }:
    let
      platforms = [
        "aarch64-linux"
        "x86_64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
    in
    flake-utils.lib.eachSystem platforms (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnsupportedSystem = true;
        };
      in
      rec {
        formatter = pkgs.nixfmt-rfc-style;

        packages = rec {
          default = hysteria;
          hysteria = pkgs.callPackage ./package.nix {
            inherit platforms src;
            inherit (self.inputs.src) lastModifiedDate rev;
            version = pkgs.lib.removePrefix "app/v" inputs.src.ref;
          };

          options = options-nix.lib.mkOptionScript {
            inherit system;
            module = self.nixosModules.default;
            modulePrefix = "services.hysteria";
          };
        };

        checks.default = pkgs.callPackage ./check { hysteria = self.nixosModules.default; };

        devShells.default = pkgs.mkShellNoCC {
          HYSTERIA_LOG_LEVEL = "debug";
          HYSTERIA_TMP = "/tmp/hysteria";

          inputsFrom = [ packages.hysteria ];

          shellHook = ''
            rm -r $HYSTERIA_TMP
            cp -r --no-preserve=mode,ownership ${src} $HYSTERIA_TMP
            cd $HYSTERIA_TMP
          '';
        };
      }
    )
    // {
      nixosModules.default = import ./module.nix self.packages;

      hydraJobs = {
        inherit (self) packages;
      };
    };
}
