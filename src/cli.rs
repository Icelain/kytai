use clap::{Parser, Subcommand};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Server {
    pub bind_addr: String,
    pub port: u16,
    pub key: String,
    pub dns: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub remote_addr: String,
    pub port: u16,
    pub key: String,
    pub default_route: bool,
}

#[derive(Debug, Clone)]
pub enum Args {
    Client(Client),
    Server(Server),
}

#[derive(Parser, Debug)]
#[command(
    name = "kytai",
    version = "1.0",
    about = "kytai: High Performance Peer-to-Peer VPN"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run in server mode
    Server {
        /// Listen address
        #[arg(short = 'l', long = "listen", default_value = "0.0.0.0")]
        bind: String,
        /// Listen port
        #[arg(short, long, default_value = "9527")]
        port: u16,
        /// Key for encrypted communication
        #[arg(short, long)]
        key: String,
        /// DNS for clients
        #[arg(short, long, default_value = "8.8.8.8")]
        dns: String,
    },
    /// Run in client mode
    Client {
        /// Remote server address
        #[arg(short, long)]
        server: String,
        /// Remote port
        #[arg(short, long)]
        port: u16,
        /// Key for encrypted communication
        #[arg(short, long)]
        key: String,
        /// Do not set default route
        #[arg(short = 'n', long = "no-default-route")]
        no_default_route: bool,
    },
}

pub fn get_args() -> Result<Args, String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Client {
            server,
            port,
            key,
            no_default_route,
        } => Ok(Args::Client(Client {
            remote_addr: server,
            port,
            key,
            default_route: !no_default_route,
        })),
        Commands::Server {
            bind,
            port,
            key,
            dns,
        } => {
            let dns = IpAddr::V4(Ipv4Addr::from_str(&dns).map_err(|e| e.to_string())?);
            Ok(Args::Server(Server {
                bind_addr: bind,
                port,
                key,
                dns,
            }))
        }
    }
}
