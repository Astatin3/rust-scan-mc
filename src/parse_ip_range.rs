use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use rand::{rng, seq::SliceRandom};

// static MAX_HOSTS: u32 = 1024;

/// Parse a comma-separated list of IP targets
/// Each target can be:
/// - Single IP: 192.168.1.1
/// - IP range: 192.168.1.1-192.168.1.10
/// - CIDR notation: 192.168.1.0/24
pub fn parse_ip_targets(targets: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let mut ips = Vec::new();

    // Split the input by commas
    for target in targets.split(',') {
        let target = target.trim();

        if target.contains('/') {
            // CIDR notation
            parse_cidr(target, &mut ips)?;
        } else if target.contains('-') {
            // IP range
            parse_ip_range(target, &mut ips)?;
        } else {
            // Single IP
            if let Ok(ip) = IpAddr::from_str(target) {
                ips.push(ip);
            }
        }
    }

    ips.shuffle(&mut rng());

    Ok(ips)
}

/// Parse CIDR notation (e.g., 192.168.1.0/24)
fn parse_cidr(cidr: &str, ips: &mut Vec<IpAddr>) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".into());
    }

    let base_ip = Ipv4Addr::from_str(parts[0])?;
    let prefix_len: u8 = parts[1].parse()?;

    if prefix_len > 32 {
        return Err("Invalid CIDR prefix length".into());
    }

    // Calculate the number of hosts in this CIDR
    let hosts = if prefix_len == 32 {
        1 // Just one host for /32
    } else {
        1u32 << (32 - prefix_len) // 2^(32-prefix_len)
    };

    // If the CIDR is too large, warn and limit
    // if hosts > MAX_HOSTS {
    //     println!(
    //         "Warning: CIDR {} contains {} hosts. Limiting to first 1024.",
    //         cidr, hosts
    //     );
    // }

    // Convert base IP to u32 for easier manipulation
    let base_ip_u32 = u32::from(base_ip);

    // Generate all IPs in the CIDR block (up to limit)
    // let limit = std::cmp::min(hosts, MAX_HOSTS);
    for i in 0..hosts {
        let ip_u32 = base_ip_u32 & (0xFFFFFFFF << (32 - prefix_len)) | i;
        let ip = Ipv4Addr::from(ip_u32);
        ips.push(IpAddr::V4(ip));
    }

    Ok(())
}

/// Parse IP range (e.g., 192.168.1.1-192.168.1.10)
fn parse_ip_range(range: &str, ips: &mut Vec<IpAddr>) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err("Invalid IP range format".into());
    }

    let start_ip = Ipv4Addr::from_str(parts[0])?;
    let end_ip = Ipv4Addr::from_str(parts[1])?;

    let start_u32 = u32::from(start_ip);
    let end_u32 = u32::from(end_ip);

    if start_u32 > end_u32 {
        return Err("Invalid IP range: start IP is greater than end IP".into());
    }

    let range_size = end_u32 - start_u32 + 1;

    // // If the range is too large, warn and limit
    // if range_size > MAX_HOSTS {
    //     println!(
    //         "Warning: IP range {}-{} contains {} hosts. Limiting to first 1024.",
    //         start_ip, end_ip, range_size
    //     );
    // }

    // let limit = std::cmp::min(range_size, MAX_HOSTS);

    // Generate all IPs in the range (up to limit)
    for i in 0..range_size {
        let ip_u32 = start_u32 + i;
        let ip = Ipv4Addr::from(ip_u32);
        ips.push(IpAddr::V4(ip));
    }

    Ok(())
}
