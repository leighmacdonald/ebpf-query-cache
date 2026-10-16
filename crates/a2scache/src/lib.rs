pub mod bpf;
pub mod daemon;
pub mod query;

use aya::include_bytes_aligned;
use clap::ValueEnum;

/// The compiled TC ingress program, embedded at build time (see build.rs).
pub const BPF_ELF: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/a2scache-bpf"));

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("ebpf: {0}")]
    Ebpf(#[from] aya::EbpfError),
    #[error("program: {0}")]
    Program(#[from] aya::programs::ProgramError),
    #[error("map: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("pin: {0}")]
    Pin(#[from] aya::pin::PinError),
    #[error("tc: {0}")]
    Tc(#[from] aya::programs::tc::TcError),
    #[error("nul: {0}")]
    Nul(#[from] std::ffi::NulError),
    #[error("bad address `{0}` (want ip:port)")]
    Addr(String),
    #[error("{0}")]
    Bad(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum QueryKind {
    /// A2S_INFO (server banner)
    Info,
    /// A2S_PLAYER (player list)
    Players,
}
