set shell := ["bash", "-uc"]
set export := true

tmp := ".tmp"
TMPDIR := ".tmp"
CARGO_TARGET_DIR := ".tmp/cargo-target"
CARGO_HOME := ".tmp/cargo-home"
RUSTUP_HOME := ".tmp/rustup"

# Print available recipes
help:
  just --list

default: build

# Hermetic build via nix (vendored deps, offline)
build:
  nix build .#a2scache --json > {{ tmp }}/build.json

# Enter the nix development shell
develop:
  nix develop -c "${SHELL:-bash}"

# Fast local build (inside `just develop` or an equivalent toolchain).
# NOTE: just runs each recipe line in its own shell; keep state on one line.
build-local:
  mkdir -p {{ tmp }} && cargo build --release -p a2scache

# Format all crates
fmt:
  cargo fmt --all

# Lint all crates (clippy, warnings as errors)
lint:
  cargo clippy --workspace --exclude a2scache-bpf --all-targets -- -D warnings

# Unit tests (protocol codec + userspace; the BPF crate is bpf-target only)
test:
  cargo test -p a2s-protocol -p a2scache

# End-to-end test (requires root/CAP_BPF: netns + fake servers)
test-e2e: build-local
  bash tests/e2e/run.sh

# Install binary, systemd units and example config
install: build
  sudo install -Dm 0755 result/bin/a2scache /usr/local/bin/a2scache
  sudo install -Dm 0644 packaging/a2scache-attach.service /etc/systemd/system/a2scache-attach.service
  sudo install -Dm 0644 packaging/a2scache-daemon.service /etc/systemd/system/a2scache-daemon.service
  sudo install -Dm 0644 examples/a2scache.toml /etc/a2scache.toml
  sudo systemctl daemon-reload

# Remove build artifacts
clean:
  rm -rf {{ tmp }}
