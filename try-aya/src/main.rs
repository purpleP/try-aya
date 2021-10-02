use aya::Bpf;
use aya_log::BpfLogger;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

use aya::programs::KProbe;
use std::{
    convert::{TryFrom,TryInto},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
};
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    
}

fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;
    let program: &mut KProbe = bpf.program_mut("do_execveat_common")?.try_into()?;
    program.load()?;
    program.attach("do_execveat_common", 0)?;
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    BpfLogger::init(
        &mut bpf,
        TermLogger::new(
            LevelFilter::Trace,
            ConfigBuilder::new()
                .set_target_level(LevelFilter::Error)
                .set_location_level(LevelFilter::Error)
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
    ).unwrap();

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {}
    println!("Exiting...");

    Ok(())
}
