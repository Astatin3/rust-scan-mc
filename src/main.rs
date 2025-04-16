pub mod online_scan;
pub mod parse_ip_range;

use std::env;

use online_scan::ping_scanner;
use parse_ip_range::parse_ip_targets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Set default targets or use command line input
    let targets = if args.len() > 1 {
        args[1].clone()
    } else {
        "".to_string()
    };

    // Parse the targets into IP addresses
    let hosts = parse_ip_targets(&targets)?;

    let length = hosts.len();

    let results = ping_scanner::ping_scan(hosts).unwrap();

    println!("Finished! {} Scanned, {} Up", length, results.len());
    Ok(())
}
