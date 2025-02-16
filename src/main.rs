use clap::Parser;
use codecrafters_dns_server::dns_server;
use std::{env, error::Error};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    resolver: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    env::set_var("RUST_BACKTRACE", "1");
    let args = Args::parse();
    println!("Using resolver: {}", args.resolver);
    let mut server = dns_server::server::Server::new("127.0.0.1".to_string(), 2053, args.resolver);
    server.start()?;
    Ok(())
}
