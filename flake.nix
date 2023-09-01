{
  description = "Rust development nix flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ 
          (import rust-overlay) 
        ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustVersion = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml);
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustVersion;
          rustc = rustVersion;
        };
      in {
        # stdenv = pkgs.clangStdenv;
        devShell = pkgs.mkShell {
          LIBCLANG_PATH = pkgs.libclang.lib + "/lib/";
          NIXPKGS_ALLOW_INSECURE=1;
          SEQUENCER_BATCH_INBOX_ADDRESS="0xff00000000000000000000000000000000000000";
          L2OO_ADDRESS="0x70997970C51812dc3A010C7d01b50e0d17dc79C";
          # LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib/:$LD_LIBRARY_PATH";

          nativeBuildInputs = with pkgs; [
            bashInteractive
            taplo
            clang
            cmake
            openssl
            pkg-config
            # clang
            llvmPackages_11.bintools
            llvmPackages_11.libclang
            protobuf

            nodejs-20
          ];
          buildInputs = with pkgs; [
              (rustVersion.override { extensions = [ "rust-src" ]; })
          ];

        };
  });
}
