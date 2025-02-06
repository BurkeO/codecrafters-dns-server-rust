use codecrafters_dns_server::dns_server;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Logs from your program will appear here!");
    let server = dns_server::server::Server::new("127.0.0.1".to_string(), 2053);
    server.start()?;
    Ok(())
}
