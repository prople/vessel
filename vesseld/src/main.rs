use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "vesseld")]
#[command(version = "1.0")]
#[command(long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>
}

fn main() {
    let cli = Cli::parse();
    if let Some(conf) = cli.config.as_deref() {
        let out = conf.to_str();
        println!("config value: {}", out.unwrap())
    }
}