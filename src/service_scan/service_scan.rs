use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};

use crate::{
    database::DatabaseResult, port_scan::port_scan::PortScanResult, service_scan::tcp_http,
};

use super::{services::SERVICE_PATTERNS, tcp_https, tcp_minecraft};

#[derive(Debug, Clone)]
pub struct ServiceScanResult {
    pub ip: IpAddr,
    pub open_ports: Vec<i32>,
    pub services: HashMap<i32, (String, String)>,
}

impl ServiceScanResult {
    fn new(ip: IpAddr) -> Self {
        ServiceScanResult {
            ip,
            open_ports: Vec::new(),
            services: HashMap::new(),
        }
    }
    pub fn to_database(&self) -> DatabaseResult {
        let data = serde_json::to_string(&self.services).unwrap_or(String::new());

        let mut services = Vec::new();

        for key in self.services.keys() {
            services.push(self.services.get(key).unwrap().0.clone());
        }

        services.sort();
        services.dedup();

        // println!("{}", data);
        DatabaseResult {
            id: self.ip.to_string(),
            ports: self.open_ports.clone(),
            services,
            responses: data,
        }
    }
}

pub fn identify(ip: IpAddr, port: &i32, timeout: Duration) -> (String, String) {
    let e = || {
        let (service, data) =
            basic_identify(ip, port, timeout).unwrap_or(("tcp".to_string(), "".to_string()));

        (match service.as_str() {
            "http" => tuple_or_none("http", tcp_http::scan(ip, port, timeout)),
            "https" => tuple_or_none("https", tcp_https::scan(ip, port, timeout)),
            "minecraft" => tuple_or_none("minecraft", tcp_minecraft::scan(ip, port, timeout)),
            _ => None,
        })
        .unwrap_or((service, data))
    };

    (match port {
        80 | 8080 | 8081 | 8082 | 8083 | 8084 | 8085 | 8086 | 8087 | 8088 | 8089 => {
            tuple_or_none("http", tcp_http::scan(ip, port, timeout))
        }
        443 | 8443 => tuple_or_none("https", tcp_https::scan(ip, port, timeout)),
        25565 | 25575 => tuple_or_none("minecraft", tcp_minecraft::scan(ip, port, timeout)),

        _ => None,
    })
    .unwrap_or(e())
}

fn tuple_or_none(
    tag: &str,
    data: Result<String, Box<dyn std::error::Error>>,
) -> Option<(String, String)> {
    if let Ok(data) = data {
        Some((tag.to_string(), data))
    } else {
        None
    }
}

pub fn scan_services(
    port_scan_results: Vec<PortScanResult>,
    num_threads: usize,
    timeout: Duration,
) -> Vec<ServiceScanResult> {
    let mut host_port_count: u64 = 0;
    let results: Arc<Mutex<Vec<ServiceScanResult>>> = Arc::new(Mutex::new(
        port_scan_results
            .iter()
            .map(|result| {
                host_port_count += result.open_ports.len() as u64;
                ServiceScanResult::new(result.ip)
            })
            .collect(),
    ));

    let mut handles = Vec::new();
    let pb = Arc::new(
        ProgressBar::new(host_port_count).with_style(
            ProgressStyle::with_template(
                "[{msg}] {wide_bar:.magenta/red} {pos}/{len} ({eta_precise})",
            )
            .unwrap(),
        ),
    );

    // Create a thread for each chunk of IPs
    let chunks = split_ips_into_chunks(port_scan_results, num_threads);
    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_hosts = chunk.clone();
        let thread_results = Arc::clone(&results);
        let thread_timeout = timeout;
        let thread_pb = Arc::clone(&pb);
        handles.push(thread::spawn(move || {
            for host in chunk_hosts {
                let ports = &host.open_ports;
                for port in ports {
                    // Try to identify the service on the port
                    let (service_name, banner) = identify(host.ip, port, thread_timeout);

                    let mut results_guard = thread_results.lock().unwrap();
                    if let Some(result) = results_guard.iter_mut().find(|r| r.ip == host.ip) {
                        result.open_ports.push(*port);
                        result.services.insert(*port, (service_name, banner));
                    }

                    thread_pb.inc(1);
                }
            }
            // println!("Finished chunk {}", i)
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    pb.clone().finish_with_message("Finished!");

    Arc::try_unwrap(results)
        .expect("Arc still has multiple owners")
        .into_inner()
        .expect("Mutex poisoned")
    // .into_iter()
    // .map(|a| {
    //     println!("{:?}", a);
    //     a
    // })
    // .collect()
}

// Helper function to split the IPs into roughly equal chunks for threading
fn split_ips_into_chunks(ips: Vec<PortScanResult>, num_chunks: usize) -> Vec<Vec<PortScanResult>> {
    let chunk_size = (ips.len() + num_chunks - 1) / num_chunks;
    let mut chunks = Vec::new();

    for chunk_idx in 0..num_chunks {
        let start = chunk_idx * chunk_size;
        if start >= ips.len() {
            break;
        }
        let end = (start + chunk_size).min(ips.len());
        chunks.push(ips[start..end].to_vec());
    }

    chunks
}

// Connect to an IP:port and send a probe
fn try_connect(ip: IpAddr, port: &i32, timeout: Duration, probe: &[u8]) -> Option<Vec<u8>> {
    let addr = SocketAddr::new(ip, *port as u16);

    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            // Set read/write timeouts
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));

            // Send the probe if it's not empty
            if !probe.is_empty() {
                if stream.write(probe).is_err() {
                    return None;
                }
            }

            // Read the response
            let mut buffer = [0; 4096]; // Larger buffer for service banners
            let mut response = Vec::new();

            // Try to read multiple times to get a complete banner
            for _ in 0..3 {
                match stream.read(&mut buffer) {
                    Ok(0) => break, // End of stream
                    Ok(bytes_read) => {
                        response.extend_from_slice(&buffer[0..bytes_read]);
                        if bytes_read < buffer.len() {
                            break; // Likely got all data if we read less than buffer size
                        }
                    }
                    Err(_) => break, // Error reading
                }

                // Small delay between reads
                thread::sleep(Duration::from_millis(50));
            }

            Some(response)
        }
        Err(_) => None, // Connection failed
    }
}

fn basic_identify(ip: IpAddr, port: &i32, timeout: Duration) -> Option<(String, String)> {
    // Try a simple connection with no probe as last resort
    if let Some(response) = try_connect(ip, port, timeout, b"\x00\n") {
        if !response.is_empty() {
            if let Some(service_name) = identify_service_from_response(&response) {
                return Some((
                    service_name.to_string(),
                    String::from_utf8_lossy(response.as_slice()).to_string(),
                ));
            }
        }

        // Port is open but service couldn't be identified
        return Some(("tcp".to_string(), "".to_string()));
    }

    None
}

fn identify_service_from_response(response: &[u8]) -> Option<&str> {
    // Convert response to string if possible
    if let Ok(response_str) = std::str::from_utf8(response) {
        // Try to match against known patterns
        for (pattern, service_name) in SERVICE_PATTERNS.iter() {
            if pattern.is_match(response_str) {
                return Some(service_name);
            }
        }
    }

    // // For binary responses, check for pattern matches
    // // Check for SSL/TLS
    // if response.len() >= 3 && response[0] == 0x16 && (response[1] == 0x03 || response[1] == 0x02) {
    //     return Some("ssl/tls");
    // }

    // // Check for MySQL protocol
    // if response.len() >= 5 && response[0] == 0x4a && response[1] == 0x00 {
    //     return Some("mysql");
    // }

    // // Check for MongoDB wire protocol
    // if response.len() >= 4
    //     && response[0] == 0x02
    //     && response[1] == 0x00
    //     && response[2] == 0x00
    //     && response[3] == 0x00
    // {
    //     return Some("mongodb");
    // }

    None
}
