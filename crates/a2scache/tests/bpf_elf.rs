//! Regression test for the embedded BPF ELF: parses it with the same
//! aya-obj version the loader uses and checks the program + maps are intact.
//! Catches build-pipeline breakage (empty sections, renamed maps, missing
//! license) without needing root / a kernel.
use aya_obj::{Object, ProgramSection};

#[test]
fn embedded_elf_has_ingress_program_and_maps() {
    let elf = a2scache::BPF_ELF;
    assert!(!elf.is_empty(), "embedded BPF ELF is empty");

    let obj = Object::parse(elf).expect("parse embedded BPF ELF");
    let prog = obj
        .programs
        .get("a2scache_ingress")
        .expect("program a2scache_ingress missing");
    assert!(
        matches!(prog.section, ProgramSection::SchedClassifier),
        "unexpected section {:?}",
        prog.section
    );
    // The program body lives in `functions`, keyed by (section, address).
    let insns: usize = obj
        .functions
        .iter()
        .filter(|((sec, _), _)| *sec == prog.section_index)
        .map(|(_, f)| f.instructions.len())
        .sum();
    assert!(insns > 0, "program has no instructions");
    println!("program a2scache_ingress: {insns} instructions");

    for map in [
        "CONFIG_MAP",
        "CACHE_MAP",
        "RATE_IP_MAP",
        "RATE_GLOBAL_MAP",
        "STATS_MAP",
    ] {
        assert!(obj.maps.contains_key(map), "map {map} missing");
    }

    assert!(
        !obj.license.is_empty(),
        "ELF has no license section (kernel would reject it)"
    );
}
