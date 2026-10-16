use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use a2scache::{bpf, daemon, query, QueryKind, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "a2scache",
    version,
    about = "eBPF A2S query cache for Source / TF2 game servers"
)]
struct Cli {
    /// bpf pin directory
    #[arg(long, global = true, default_value = bpf::DEFAULT_PIN_DIR)]
    pin_dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Attach the TC classifier to an interface
    Attach {
        /// Interface to attach on
        iface: String,
        /// Cache TTL in seconds
        #[arg(long, default_value_t = bpf::DEFAULT_TTL_SEC)]
        ttl_sec: u64,
    },
    /// Detach the program from an interface
    Detach {
        /// Interface the program is attached on
        iface: String,
    },
    /// Detach and remove all pins
    Clean {
        /// Interface the program is attached on
        iface: String,
    },
    /// Show config and cache entries
    Status,
    /// Show verdict counters (percpu-aggregated)
    Stats {
        /// Watch mode: refresh interval in seconds
        #[arg(short, long)]
        watch: Option<u64>,
        /// Output JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Query a server, performing the full challenge dance (debug)
    Query {
        /// Target `ip:port`
        addr: String,
        /// Query type
        kind: QueryKind,
        /// Per-datagram receive timeout in milliseconds
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
    },
    /// Run the refresh daemon: keep cache entries warm from a TOML config
    Serve {
        /// Daemon config file
        #[arg(long, default_value = "/etc/a2scache.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    env_logger::init();
    let cli = Cli::parse();

    let res = match &cli.cmd {
        Cmd::Attach { iface, ttl_sec } => {
            bpf::attach(a2scache::BPF_ELF, iface, &cli.pin_dir, *ttl_sec)
        }
        Cmd::Detach { iface } => bpf::detach(iface),
        Cmd::Clean { iface } => bpf::clean(iface, &cli.pin_dir),
        Cmd::Status => bpf::status(&cli.pin_dir),
        Cmd::Stats { watch, json } => stats_loop(&cli.pin_dir, *watch, *json),
        Cmd::Query {
            addr,
            kind,
            timeout_ms,
        } => query::run(addr, *kind, *timeout_ms),
        Cmd::Serve { config } => {
            // An explicit --pin-dir wins; otherwise the daemon config's
            // [bpf] pin_dir applies.
            let override_dir = if cli.pin_dir.as_os_str() != bpf::DEFAULT_PIN_DIR {
                Some(cli.pin_dir.as_path())
            } else {
                None
            };
            daemon::serve(config, override_dir)
        }
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("a2scache: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn stats_loop(pin_dir: &Path, watch: Option<u64>, json: bool) -> Result<()> {
    loop {
        let totals = bpf::stats(pin_dir)?;
        if json {
            let parts: Vec<String> = bpf::STATS_NAMES
                .iter()
                .zip(&totals)
                .map(|(n, v)| format!("\"{n}\": {v}"))
                .collect();
            println!("{{{}}}", parts.join(", "));
        } else {
            for (name, v) in bpf::STATS_NAMES.iter().zip(&totals) {
                println!("{name:<24} {v}");
            }
        }
        let Some(secs) = watch else { return Ok(()) };
        std::thread::sleep(Duration::from_secs(secs));
    }
}
