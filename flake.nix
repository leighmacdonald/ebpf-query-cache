{
  description = "eBPF A2S query cache for Source (TF2) game servers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # Rust nightly (pinned via flake.lock). rustup ships no prebuilt std for
    # bpfel/bpfeb-unknown-none, so the BPF crate is built with -Z build-std
    # (see crates/a2scache/build.rs) using the rust-src component below.
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll =
        f:
        nixpkgs.lib.genAttrs systems (
          s:
          f {
            inherit s;
            pkgs = nixpkgs.legacyPackages.${s};
            # The musl triple of the build system; the package is built for
            # it so the binary is fully static and runs on plain Ubuntu.
            muslTarget =
              if s == "x86_64-linux" then "x86_64-unknown-linux-musl" else "aarch64-unknown-linux-musl";
            # Pinned nightly toolchain: host compiler + lints + rust-src
            # (for -Z build-std of the BPF crate) + musl target std (for
            # the fully static binary that runs on plain Ubuntu).
            nightly =
              let
                mt = if s == "x86_64-linux" then "x86_64-unknown-linux-musl" else "aarch64-unknown-linux-musl";
              in
              fenix.packages.${s}.combine [
                fenix.packages.${s}.latest.rustc
                fenix.packages.${s}.latest.cargo
                fenix.packages.${s}.latest.clippy
                fenix.packages.${s}.latest.rustfmt
                fenix.packages.${s}.latest.rust-src
                fenix.packages.${s}.targets.${mt}.latest.rust-std
              ];
            # bpf-linker newer than nixpkgs': the 0.9.x in nixos-26.05
            # cannot read the LLVM bitcode of current nightly rustc
            # ("ERROR llvm: Invalid record"). Pinned upstream musl-static
            # release binaries (fully static, run anywhere).
            bpfLinker =
              let
                asset =
                  {
                    x86_64-linux = {
                      file = "bpf-linker-x86_64-unknown-linux-musl.tar.zst";
                      hash = "sha256-Z4lxfIy2oqXZIPO2v6wr1+/AD2Io7NFJEIqZaZp1xnk=";
                    };
                    aarch64-linux = {
                      file = "bpf-linker-aarch64-unknown-linux-musl.tar.zst";
                      hash = "sha256-XiAeadr6x6+Y+XiPHGjt1czI+ggFCT+Jm/Ar0pR7OTU=";
                    };
                  }
                  .${s};
                _pkgs = nixpkgs.legacyPackages.${s};
              in
              _pkgs.stdenvNoCC.mkDerivation {
                pname = "bpf-linker";
                version = "0.12.0";
                src = _pkgs.fetchurl {
                  url = "https://github.com/aya-rs/bpf-linker/releases/download/v0.12.0/${asset.file}";
                  hash = asset.hash;
                };
                nativeBuildInputs = [ _pkgs.zstd ];
                # The tarball holds a single static `bpf-linker` binary
                # (no directory), so unpack it by hand.
                unpackPhase = ''
                  runHook preUnpack
                  unzstd -c "$src" | tar -x
                  runHook postUnpack
                '';
                installPhase = ''
                  mkdir -p $out/bin
                  install -m 0755 bpf-linker $out/bin/bpf-linker
                '';
              };
          }
        );
      # Source tree without local build state.
      src = nixpkgs.lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          let
            name = nixpkgs.lib.baseNameOf (toString path);
          in
          name != ".tmp" && name != "result" && name != "result-a2scache";
      };
    in
    {
      devShells = forAll (
        {
          pkgs,
          nightly,
          bpfLinker,
          ...
        }:
        {
          default = pkgs.mkShell {
            packages = [
              nightly
              bpfLinker
              pkgs.just
              pkgs.bpftools
              pkgs.iproute2
            ];
          };
        }
      );

      packages = forAll (
        {
          pkgs,
          nightly,
          bpfLinker,
          muslTarget,
          ...
        }:
        rec {
          # Single static binary (musl) with the BPF ELF embedded
          # (compiled for bpfel-unknown-none by the a2scache crate's build
          # script). musl => runs on plain Ubuntu without a Nix glibc.
          a2scache =
            (pkgs.rustPlatform.buildRustPackage.override {
              stdenv = pkgs.stdenvNoCC;
              cargo = nightly;
              rustc = nightly;
            })
              {
                pname = "a2scache";
                version = "0.1.0";
                src = src;

                # Vendored via fetchurl at nix time; the build itself is offline.
                cargoLock = {
                  lockFile = ./Cargo.lock;
                };

                nativeBuildInputs = [
                  bpfLinker
                ];

                auditable = false;
                doCheck = false;

                buildPhase = ''
                  runHook preBuild
                  # Self-contained musl link (rust-lld + bundled crt); stdenv
                  # has no cc and the musl target does not default to
                  # self-contained on this toolchain. Target-scoped so host
                  # crates (build.rs, proc-macros) keep the gnu defaults.
                  export CARGO_TARGET_$(echo ${muslTarget} | tr 'a-z-' 'A-Z_')_RUSTFLAGS="-C link-self-contained=y -C linker=rust-lld -C linker-flavor=ld.lld"
                  cargo build --release --offline -p a2scache --target ${muslTarget}
                  runHook postBuild
                '';
                installPhase = ''
                  mkdir -p $out/bin
                  install -m 0755 target/${muslTarget}/release/a2scache $out/bin/a2scache
                '';
              };

          default = a2scache;
        }
      );
    };
}
