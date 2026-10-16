# Vendored aya-obj 0.3.0 (patched)

Source: aya-obj 0.3.0 from crates.io, used via `[patch.crates-io]` in the
workspace `Cargo.toml` so `aya 0.14` picks it up.

## Why vendored

`src/relocation.rs` (`FunctionLinker`) carries two fixes that upstream
aya-obj 0.3.0/0.4.0 lack; without them our TC program is rejected by the
kernel verifier with "last insn is not an exit or jmp" (processed 0 insns):

1. **Dedup key is (section, address), not address alone.** Function
   addresses repeat across sections (e.g. the first function of `.text`
   and of `.text.unlikely.` both live at address 0). Keying by address
   alone mislinks same-address callees into each other: a call to
   `panic_fmt` (.text.unlikely., addr 0) was rewritten to jump to
   `rate_limited_pass` (.text, addr 0), leaving a one-instruction
   pseudo-function ending in a `call` that the verifier rejects.
2. **Resolved static calls get `src_reg = BPF_K`.** After rewriting the
   call immediate to a pc-relative offset, the `BPF_PSEUDO_CALL` marker
   must be cleared; otherwise the kernel still treats the instruction as
   an unresolved pseudo-call.

Both hunks are marked with `ebpf-query-cache:` comments.

## Maintenance

- Re-check against upstream on every `aya`/`bpf-linker`/nightly bump:
  if upstream fixed `relocation.rs`, drop this patch.
- `vendor/` must stay committed: flake path inputs (and hence `nix build`)
  only ship git-tracked files.
