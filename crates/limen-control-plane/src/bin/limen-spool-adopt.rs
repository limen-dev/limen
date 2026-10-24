//! Hand a leftover audit spool to a live control plane replica.
//!
//!   limen-spool-adopt --dir /var/lib/limen/spool --expect-id cp-3
//!
//! Run with the environment of a control plane replica (database URL, CA
//! settings). Exits 0 only when every unshipped record was acked by a peer
//! and the spool has nothing pending; non-zero otherwise.

use clap::Parser;
use limen_control_plane::adopt::{self, AdoptArgs};
use limen_core::telemetry::LogArgs;

#[derive(Debug, Parser)]
#[command(name = "limen-spool-adopt", version = limen_core::VERSION, about)]
struct Args {
    #[command(flatten)]
    log: LogArgs,

    #[command(flatten)]
    adopt: AdoptArgs,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    args.log.init();
    match adopt::run(args.adopt).await {
        Ok(done) => match done.peer {
            Some(peer) => eprintln!("OK: handed {} audit records to {peer}", done.sent),
            None => eprintln!("OK: the spool had nothing left to hand off"),
        },
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(2);
        }
    }
}
