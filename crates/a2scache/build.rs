//! Builds the `a2scache-bpf` crate for `bpfel/bpfeb-unknown-none` and copies
//! the resulting ELF into `OUT_DIR/a2scache-bpf` for `include_bytes!`.
//!
//! This mirrors `aya-build`: nightly cargo with `-Z build-std=core` compiles
//! `core` for the BPF target from the toolchain's `rust-src` (rustup ships
//! no prebuilt std for the bpf targets). No `RUSTC_BOOTSTRAP` hack is needed:
//! the toolchain is nightly, so `-Z` flags and aya-ebpf's
//! `asm_experimental_arch` work natively.
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");

    println!("cargo:rerun-if-changed={manifest}/../a2scache-bpf");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    if let Ok(skip) = std::env::var("AYA_BUILD_SKIP")
        && (skip == "1" || skip.eq_ignore_ascii_case("true"))
    {
        eprintln!("AYA_BUILD_SKIP={skip}; skipping eBPF build");
        return;
    }

    let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN").expect("CARGO_CFG_TARGET_ENDIAN");
    let prefix = match endian.as_str() {
        "big" => "bpfeb",
        "little" => "bpfel",
        other => panic!("unsupported endian={other}"),
    };
    // Host architecture, used for `--cfg bpf_target_arch` (aya-ebpf layout
    // hints); BPF bytecode itself is architecture independent.
    let host_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let target = format!("{prefix}-unknown-none");

    let target_dir = format!("{out_dir}/aya-build-target");
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "-Z",
        "build-std=core",
        "--package",
        "a2scache-bpf",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        target.as_str(),
    ])
    .arg("--target-dir")
    .arg(target_dir.as_str())
    .env(
        "CARGO_ENCODED_RUSTFLAGS",
        format!("--cfg=bpf_target_arch=\"{host_arch}\"\u{1f}-Cdebuginfo=2\u{1f}-Clink-arg=--btf"),
    )
    // bpf-linker is the BPF target linker in both the dev shell and the nix
    // package sandbox (provided via PATH); spell it out so the inner build
    // does not depend on rustc-wrapper defaults.
    .env(
        format!(
            "CARGO_TARGET_{}_LINKER",
            target.to_uppercase().replace('-', "_")
        ),
        "bpf-linker",
    )
    .env_remove("RUSTC")
    .env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn inner cargo: {e}"));
    assert!(status.success(), "inner bpf build failed: {status}");

    let src = format!("{target_dir}/{target}/release/a2scache-bpf");
    let dst = format!("{out_dir}/a2scache-bpf");
    std::fs::copy(&src, &dst).unwrap_or_else(|e| panic!("failed to copy {src} -> {dst}: {e}"));
    strip_btf_ext_func_info(&dst);
}

/// Neutralize the `.BTF.ext` func_info section of the linked ELF (in place).
///
/// Background: rustc emits a cold trap epilogue (a call into a
/// single-instruction trap in `.text.unlikely.`) after `main`'s real end,
/// and bpf-linker records func_info for it. The kernel verifier only counts
/// *live* subprograms discovered from the call graph, so the dead trap's
/// record trips "number of funcs in func_info doesn't match number of
/// subprogs" at load. Without func_info the verifier discovers subprograms
/// from calls itself and the dead trap is simply never visited.
///
/// Only the `func_info_len` header field is zeroed; the section stays valid
/// (aya parses an empty func_info fine) and `.BTF`/line_info are untouched,
/// so map BTF and source correlation keep working.
fn strip_btf_ext_func_info(path: &str) {
    let mut elf = std::fs::read(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let u16le = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let u32le = |b: &[u8]| u32::from_le_bytes(b[0..4].try_into().unwrap());
    let u64le = |b: &[u8]| u64::from_le_bytes(b[0..8].try_into().unwrap());

    assert!(
        elf.len() > 64 && &elf[0..4] == b"\x7fELF" && elf[4] == 2 && elf[5] == 1,
        "not a 64-bit little-endian ELF: {path}"
    );
    let shoff = u64le(&elf[0x28..]) as usize;
    let shentsize = u16le(&elf[0x3A..]) as usize;
    let shnum = u16le(&elf[0x3C..]) as usize;
    let shstrndx = u16le(&elf[0x3E..]) as usize;
    let sh = |i: usize| &elf[shoff + i * shentsize..];

    let strtab = {
        let h = sh(shstrndx);
        let (off, size) = (u64le(&h[24..]) as usize, u64le(&h[32..]) as usize);
        &elf[off..off + size]
    };
    let name_of = |h: &[u8]| {
        let mut n = u32le(&h[0..]) as usize;
        let mut name = Vec::new();
        while strtab[n] != 0 {
            name.push(strtab[n]);
            n += 1;
        }
        String::from_utf8(name).unwrap()
    };

    for i in 0..shnum {
        if name_of(sh(i)) != ".BTF.ext" {
            continue;
        }
        let h = sh(i);
        let (off, size) = (u64le(&h[24..]) as usize, u64le(&h[32..]) as usize);
        assert!(size >= 32, ".BTF.ext too small in {path}");
        // btf_ext_header: magic u16, ver u8, flags u8, hdr_len u32,
        // func_info_off u32, func_info_len u32, ...
        let magic = u16le(&elf[off..]);
        assert!(magic == 0xeb9f, "bad BTF.ext magic in {path}");
        // Zero func_info_len; keep func_info_off (harmless once len is 0).
        elf[off + 12..off + 16].copy_from_slice(&0u32.to_le_bytes());
        std::fs::write(path, &elf).unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
        eprintln!("stripped BTF.ext func_info from {path}");
        return;
    }
    panic!("no .BTF.ext section in {path}");
}
