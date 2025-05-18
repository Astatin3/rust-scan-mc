use std::{
    cmp::min,
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;

use crate::{
    database::DatabaseResult, port_scan::port_scan::PortScanResult, service_scan::tcp_http,
};

use super::tcp_minecraft;

// #[derive(Debug, Clone)]
// pub struct ServiceScanResult {
//     pub ip: IpAddr,
//     pub open_ports: Vec<i32>,
//     pub services: HashMap<i32, (String, String)>,
// }

// impl ServiceScanResult {
//     fn new(ip: IpAddr) -> Self {
//         ServiceScanResult {
//             ip,
//             open_ports: Vec::new(),
//             services: HashMap::new(),
//         }
//     }
//     pub fn to_database(&self) -> DatabaseResult {
//         let data = serde_json::to_string(&self.services).unwrap_or(String::new());

//         let mut services = Vec::new();

//         for key in self.services.keys() {
//             services.push(self.services.get(key).unwrap().0.clone());
//         }

//         services.sort();
//         services.dedup();

//         // println!("{}", data);
//         DatabaseResult {
//             ip: self.ip.to_string(),
//             ports: self.open_ports.clone(),
//             services,
//             responses: data,
//         }
//     }
// }

pub fn identify(ip: IpAddr, port: &i32, timeout: Duration) -> Option<DatabaseResult> {
    // println!("primary");

    tcp_minecraft::scan(ip, port, timeout).ok()

    // basic_identify(ip, port, timeout).unwrap_or(("tcp".to_string(), "".to_string()))
}

pub fn scan_services(
    port_scan_results: Vec<PortScanResult>,
    num_threads: usize,
    timeout: Duration,
) -> Vec<DatabaseResult> {
    let mut host_port_count: usize = 0;

    let results: Arc<Mutex<Vec<DatabaseResult>>> = Arc::new(Mutex::new(Vec::new()));

    let mut host_port: Vec<(IpAddr, i32)> = Vec::new();
    for host in &port_scan_results {
        for port in &host.open_ports {
            host_port.push((host.ip, port.clone()));
        }
        host_port_count += host.open_ports.len();
    }

    host_port.shuffle(&mut rand::rng());

    let host_port = Arc::new(Mutex::new(host_port));

    let mut handles = Vec::new();
    let pb = Arc::new(
        ProgressBar::new(host_port_count as u64).with_style(
            ProgressStyle::with_template(
                "[{msg}] {wide_bar:.magenta/red} {pos}/{len} ({eta_precise})",
            )
            .unwrap(),
        ),
    );

    // Create a thread for each chunk of IPs
    // let chunks = split_ips_into_chunks(port_scan_results, num_threads);
    for _ in 0..=min(num_threads, host_port_count) {
        // println!("Thread {},{}", i, chunk.len());
        // let chunk_hosts = chunk.clone();
        let thread_hosts = Arc::clone(&host_port);
        let thread_results = Arc::clone(&results);
        let thread_timeout = timeout;
        let thread_pb = Arc::clone(&pb);
        handles.push(thread::spawn(move || {
            loop {
                let mut hosts = thread_hosts.lock().unwrap();
                // println!("{}, {}, {}", i, hosts.len(), total_count);

                if hosts.len() == 0 {
                    // println!("Break thread {} A", i);
                    break;
                }

                let host = hosts.pop();

                std::mem::drop(hosts);

                if host.is_none() {
                    // println!("Break thread {} B", i);
                    break;
                }
                let host = host.unwrap();

                let ip = host.0;
                let port = host.1;

                // println!("{}, {}, {}", i, ip, port);

                // Try to identify the service on the port
                // println!("Thread {} stall 2", i);
                let result = identify(ip, &port, thread_timeout);
                // println!("Thread {} stall 3", i);

                if let Some(result) = result {
                    let mut results_guard = thread_results.lock().unwrap();
                    thread_pb.set_message(format!("{} Found", results_guard.len()));
                    // println!("{}, {}", i, result.to_string());
                    results_guard.push(result);
                    std::mem::drop(results_guard);
                }

                // println!("Thread {} stall 4", i);

                thread_pb.inc(1);
                // println!("Thread {}", i);

                // total_count += 1;
            }
            // println!("Thread {}", i);
            // println!("Finished chunk {}", i)
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let results = Arc::try_unwrap(results)
        .expect("Arc still has multiple owners")
        .into_inner()
        .expect("Mutex poisoned");

    pb.clone()
        .finish_with_message(format!("Finished! {} Found", results.len()));

    results
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
fn try_connect(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
    probe: &[u8],
    delay: u64,
) -> Option<Vec<u8>> {
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

// fn basic_identify(ip: IpAddr, port: &i32, timeout: Duration) -> Option<(String, String)> {
//     // println!("Start try_connect");
//     // Try a simple connection with no probe as last resort
//     if let Some(response) = try_connect(ip, port, timeout, b"\x00\n") {
//         if !response.is_empty() {
//             if let Some(service_name) = identify_service_from_response(&response) {
//                 return Some((
//                     service_name.to_string(),
//                     String::from_utf8_lossy(response.as_slice()).to_string(),
//                 ));
//             }
//         }

//         // println!("End try_connect1");

//         // Port is open but service couldn't be identified
//         return Some(("tcp".to_string(), "".to_string()));
//     }

//     // println!("Start try_connect2");

//     None
// }
