//! TEMPORARY debug: disassemble ranges of the embedded/linked BPF program.
//! BPF_DUMP_PATH overrides the ELF source; BPF_DUMP_RANGE="a..b" selects
//! merged-array indices (default: whole main + call summary).
use aya_obj::Object;
use std::collections::HashSet;

fn fmt_insn(ins: &aya_obj::generated::bpf_insn) -> String {
    format!(
        "code={:#04x} dst={} src={} off={} imm={}",
        ins.code,
        ins.dst_reg(),
        ins.src_reg(),
        ins.off,
        ins.imm
    )
}

#[test]
fn dump_functions() {
    let data;
    let elf: &[u8] = match std::env::var("BPF_DUMP_PATH").ok().as_deref() {
        Some(p) => {
            data = std::fs::read(p).unwrap();
            &data
        }
        None => a2scache::BPF_ELF,
    };
    let _ = env_logger::builder().is_test(true).try_init();

    let mut obj = Object::parse(elf).expect("parse");
    let text_sections: HashSet<usize> = obj.functions.keys().map(|(s, _)| *s).collect();
    obj.relocate_calls(&text_sections).expect("relocate calls");
    let prog = obj.programs.get("a2scache_ingress").unwrap();
    let main = obj.functions.get(&prog.function_key()).unwrap();
    let n = main.instructions.len();
    println!("merged insns: {n}");

    // Source lines for insns of interest (from BTF line_info).
    let targets = [550usize, 582, 583];
    let btf = obj.btf.as_ref().unwrap();
    for li in &main.line_info.line_info {
        if targets.contains(&(li.insn_off as usize)) {
            let file = btf
                .strings
                .get(li.file_name_off as usize)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .unwrap_or_default();
            println!("  insn {}: {}:{}", li.insn_off, file, li.line_off >> 10);
        }
    }

    // CFG reachability over the merged array (calls followed, helpers opaque).
    // ldimm64 (0x18) occupies two slots; the second half is not an insn.
    let mut is_insn = vec![true; n];
    for (i, ins) in main.instructions.iter().enumerate() {
        if ins.code == 0x18 && i + 1 < n {
            is_insn[i + 1] = false;
        }
    }
    let mut reached = vec![false; n];
    let mut work = vec![0usize];
    let mut calls = vec![];
    let mut trace = 0;
    while let Some(pc) = work.pop() {
        if pc >= n || !is_insn[pc] || reached[pc] {
            continue;
        }
        reached[pc] = true;
        let ins = &main.instructions[pc];
        if trace < 25 {
            println!(
                "  walk pc={pc}: code={:#04x} dst={} src={} off={} imm={}",
                ins.code,
                ins.dst_reg(),
                ins.src_reg(),
                ins.off,
                ins.imm
            );
            trace += 1;
        }
        let op = ins.code & 0xf0;
        let klass = ins.code & 0x07;
        // ldimm64 (0x18) occupies two slots; successors are past both.
        let fall = if ins.code == 0x18 { pc + 2 } else { pc + 1 };
        if ins.code == 0x85 {
            // call: helper (src==0, small imm) or static (src==1 or patched)
            if ins.src_reg() == 0 && ins.imm >= 0 && ins.imm < 64 {
                // kernel helper: falls through
                work.push(fall);
            } else {
                let target = pc as i64 + 1 + ins.imm as i64;
                calls.push((pc, target));
                work.push(target as usize);
                work.push(fall); // returns
            }
        } else if klass == 0x05 {
            if op == 0x00 {
                // JA: unconditional
                work.push((pc as i64 + 1 + ins.off as i64) as usize);
            } else if op == 0x90 {
                // EXIT: terminates
            } else {
                // conditional jump: both ways
                work.push(fall);
                work.push((pc as i64 + 1 + ins.off as i64) as usize);
            }
        } else {
            work.push(fall);
        }
    }
    let dead: Vec<usize> = (0..n).filter(|i| is_insn[*i] && !reached[*i]).collect();
    println!("static calls followed: {calls:?}");
    println!("unreachable insns: {dead:?}");
}
