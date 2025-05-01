mod ports;

use std::{
    cmp::min,
    mem,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use parse_ip_range::parse_ip_targets;
use rand::{rng, seq::SliceRandom};
use untitled::{
    database::ResultDatabase,
    online_scan,
    parse_ip_range::{self, generate_random_ipv4_addresses},
    port_scan::tcp_scan,
    query,
    service_scan::service_scan::scan_services,
};

const HILBERT_VIS_SIZE: usize = 256;

/// A fictional versioning CLI
#[derive(Debug, Parser)]
#[command(name = "rust-scan-mc")]
#[command(about = "Tool for scanning Minecraft servers", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scans servers
    #[command(arg_required_else_help = true)]
    Scan {
        /// List of remote servers
        hosts: String,

        /// Size of block of IPs to scan
        #[arg(short, long, default_value_t = 4096)]
        batch_size: usize,
        /// The top N most common ports to scan
        #[arg(short, long, default_value_t = 150)]
        n_ports: usize,
        /// Timeout for requests
        #[arg(short, long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Delay between icmp echo requests
        #[arg(short, long, default_value_t = 80)]
        ping_delay_micros: u64,
        /// Delay between tcp syn packets
        #[arg(short, long, default_value_t = 100)]
        syn_tcp_delay_micros: u64,
    },
    /// Retrieves queries
    #[command(arg_required_else_help = true)]
    Search {
        /// The search query
        query: Vec<String>,
    },
    /// Rescans servers from search query
    Rescan {
        /// The search query
        query: Vec<String>,

        /// Size of block of IPs to scan
        #[arg(short, long, default_value_t = 4096)]
        batch_size: usize,
        /// The top N most common ports to scan
        #[arg(short, long, default_value_t = 150)]
        n_ports: usize,
        /// Timeout for requests
        #[arg(short, long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Delay between icmp echo requests
        #[arg(short, long, default_value_t = 80)]
        ping_delay_micros: u64,
        /// Delay between tcp syn packets
        #[arg(short, long, default_value_t = 100)]
        syn_tcp_delay_micros: u64,
    },
    /// Scans random services
    Random {
        /// Size of block of IPs to scan
        #[arg(short, long, default_value_t = 4096)]
        batch_size: usize,
        /// The top N most common ports to scan
        #[arg(short, long, default_value_t = 150)]
        n_ports: usize,
        /// Timeout for requests
        #[arg(short, long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Delay between icmp echo requests
        #[arg(short, long, default_value_t = 80)]
        ping_delay_micros: u64,
        /// Delay between tcp syn packets
        #[arg(short, long, default_value_t = 100)]
        syn_tcp_delay_micros: u64,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let database = ResultDatabase::new("ping_result_database");

    match args.command {
        Commands::Scan {
            hosts,
            batch_size,
            n_ports,
            timeout_ms,
            ping_delay_micros,
            syn_tcp_delay_micros,
        } => {
            let hosts = parse_ip_targets(&hosts)?;

            scan(
                batch_size,
                &database,
                hosts,
                ports::PORTS[0..n_ports].to_vec(),
                Duration::from_millis(timeout_ms),
                Duration::from_micros(ping_delay_micros),
                Duration::from_micros(syn_tcp_delay_micros),
            )?;
        }
        Commands::Rescan {
            query,
            batch_size,
            n_ports,
            timeout_ms,
            ping_delay_micros,
            syn_tcp_delay_micros,
        } => {
            let start = Instant::now();
            if let Ok(query) = query::search(query) {
                let results = database.search(query);
                if let Ok(results) = results {
                    let len = results.len();

                    let mut hosts: Vec<IpAddr> = Vec::new();

                    for result in results {
                        println!("{}", result.to_string());
                        hosts.push(IpAddr::from_str(result.ip.as_str()).unwrap());
                    }
                    println!("{} results in {}ms", len, start.elapsed().as_millis());

                    hosts.sort();
                    hosts.dedup();
                    hosts.shuffle(&mut rng());

                    scan(
                        batch_size,
                        &database,
                        hosts,
                        ports::PORTS[0..n_ports].to_vec(),
                        // (1..65535).collect(),
                        Duration::from_millis(timeout_ms),
                        Duration::from_micros(ping_delay_micros),
                        Duration::from_micros(syn_tcp_delay_micros),
                    )?;
                }
            }
        }
        Commands::Search { query } => {
            let start = Instant::now();
            if let Ok(query) = query::search(query) {
                let results = database.search(query);
                if let Ok(results) = results {
                    let len = results.len();

                    for result in results {
                        println!("{}", result.to_string());
                    }
                    println!("{} results in {}ms", len, start.elapsed().as_millis());
                }
            }
        }
        Commands::Random {
            batch_size,
            n_ports,
            timeout_ms,
            ping_delay_micros,
            syn_tcp_delay_micros,
        } => loop {
            let hosts = generate_random_ipv4_addresses(
                batch_size,
                vec![
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.0.0/29",
                    "192.0.0.170/32",
                    "192.0.0.171/32",
                    "192.0.2.0/24",
                    "192.88.99.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "240.0.0.0/4",
                    "255.255.255.255/32",
                    "131.215.0.0/16",
                    "134.4.0.0/16",
                    "192.12.19.0/24",
                    "192.31.43.0/24",
                    "192.41.208.0/24",
                    "192.43.243.0/24",
                    "192.54.249.0/24",
                ],
            );

            scan(
                batch_size,
                &database,
                hosts,
                ports::PORTS[0..n_ports].to_vec(),
                Duration::from_millis(timeout_ms),
                Duration::from_micros(ping_delay_micros),
                Duration::from_micros(syn_tcp_delay_micros),
            )?;
        },
        _ => {}
    }

    Ok(())
}

fn scan(
    batch_size: usize,
    database: &ResultDatabase,
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    timeout: Duration,
    ping_delay: Duration,
    tcp_delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let mut server_count = 0;

    let chunks = hosts.chunks(batch_size);
    let num_chunks = chunks.len();
    for (i, hosts) in chunks.enumerate() {
        let hosts = hosts.to_vec();
        let length = hosts.len();

        println!("Scanning chunk {}/{} ({} hosts)", i + 1, num_chunks, length);

        let up_hosts: Vec<IpAddr> =
            online_scan::ping_scanner::ping_scan(hosts, timeout, ping_delay).unwrap();
        let up_len = up_hosts.len();
        println!(
            "Finished Pinging! {} Scanned, {} Up",
            length,
            up_hosts.len()
        );

        let tcp_results = tcp_scan::tcp_scan(up_hosts, &ports, timeout, tcp_delay);
        println!("Finished port scan");

        let service_results = scan_services(tcp_results, min(50, up_len), timeout);
        println!("Finished service scan");
        server_count += service_results.len();
        let _ = database.add_data_row(service_results);
    }

    println!("Total Servers: {}", server_count);
    let elapsed = start_time.elapsed().as_secs_f32() / 60.;
    println!("Total Elapsed: {} min", elapsed);
    println!("Rate: {} servers/min", (server_count as f32 / elapsed));

    Ok(())
}
