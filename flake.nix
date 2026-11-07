{
  description = "A small static HTTP reverse proxy with ASN and User-Agent quotas";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      forLinux = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in {
      packages = forLinux (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in {
          default = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
            pname = "blockade";
            version = "0.1.4";
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            auditable = false;
            stripAllList = [ "bin" ];
            allowedReferences = [ ];
            meta.license = pkgs.lib.licenses.mit;
          };
        });

      devShells = forLinux (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in {
          default = pkgs.mkShell {
            packages = with pkgs; [ cargo rustc rustfmt clippy ];
          };
        });
    };
}
