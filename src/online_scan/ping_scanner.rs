use indicatif::ProgressBar;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{
    Packet,
    icmp::{IcmpTypes, echo_request::MutableEchoRequestPacket},
};
use pnet::transport::{
    TransportChannelType, TransportProtocol, icmp_packet_iter, transport_channel,
};
use pnet::util::checksum;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static TIMEOUT: Duration = Duration::from_secs(3);
// static MAX_PINGS_PER_SECOND: u64 = 10000;
static SEND_DELAY_NANOS: Duration = Duration::from_micros(10);

pub fn ping_scan(hosts: Vec<IpAddr>) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let results = Arc::new(Mutex::new(Vec::<IpAddr>::new()));

    // Create a receiver channel for ICMP packets
    let (_, mut rx) = transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;

    // Create a map to store host identifiers
    let requests: Arc<Mutex<HashMap<u16, IpAddr>>> = Arc::new(Mutex::new(HashMap::new()));

    let finished_sending_time = Arc::new(AtomicBool::new(false));

    // Set up the receiver thread
    // let recv_identifiers = Arc::clone(&identifiers);
    let recv_results = Arc::clone(&results);
    let recv_requests = Arc::clone(&requests);
    let recv_finished_sending_time = Arc::clone(&finished_sending_time);
    let receiver_handle = thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut rx);
        let mut finish_sending_time: Option<Instant> = None;
        // let mut pb: Option<ProgressBar> = None;

        // Keep receiving until timeout or all hosts are accounted for
        loop {
            // Stop reciving loop if timeout is reached
            // let time = finished_sending_time;
            if finish_sending_time.is_some() {
                let delay = finish_sending_time.unwrap().elapsed();
                // pb.as_ref().unwrap().set_position(delay.as_millis() as u64);
                if delay >= TIMEOUT {
                    // pb.unwrap().finish_and_clear();
                    break;
                }
            } else if finish_sending_time.is_none()
                && recv_finished_sending_time.load(Ordering::Relaxed)
            {
                finish_sending_time = Some(Instant::now());
                // pb = Some(ProgressBar::new(TIMEOUT.as_millis() as u64));
                println!("Waiting {} seconds for timeout...", TIMEOUT.as_secs())
            }
            // if time.is_some() {
            //     println!("{}", time.unwrap().elapsed().as_millis())
            // }
            // if time.is_some() && time.unwrap().elapsed() >= TIMEOUT {
            //     break;
            // };

            match iter.next_with_timeout(Duration::from_millis(3)) {
                Ok(Some((packet, _))) => {
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        let payload = packet.payload();
                        let id = ((payload[2] as u16) << 8) + (payload[3] as u16);

                        let host_option = {
                            let ids = recv_requests.lock().unwrap();
                            ids.get(&id).cloned()
                        };

                        if let Some(host) = host_option {
                            let mut results = recv_results.lock().unwrap();
                            results.push(host);
                            // results.push(PingResult {
                            //     host,
                            //     is_up: true,
                            //     response_time: Some(response_time),
                            // });

                            // println!("Up! {0} {1}ms", host, response_time.as_millis());
                        }
                    }
                }
                Ok(None) => { /* Timeout, continue */ }
                Err(_) => break,
            }
        }
    });

    // Spawn sender threads

    let sender_requests = Arc::clone(&requests);
    // let sender_results = Arc::clone(&results);
    let sender_finished_sending_time = Arc::clone(&finished_sending_time);
    let sender_handle = thread::spawn(move || {
        let pb = ProgressBar::new(hosts.len() as u64);
        // let mut last_send_time = Instant::now();
        for (i, host) in hosts.iter().enumerate() {
            let host_clone = host.clone();

            // Use the index as a unique identifier for each host
            let identifier: u16 = i as u16;

            // Store the host-identifier mapping
            {
                let mut ids = sender_requests.lock().unwrap();
                ids.insert(identifier, host_clone);
            }

            let _ = send_ping(host_clone, identifier);

            // let now = Instant::now();
            // let delay = MAX_RATE_NANOS - last_send_time.duration_since(now).as_nanos() as u64;
            // last_send_time = now;
            if (i % 16) == 0 {
                pb.inc(16);
            }
            thread::sleep(SEND_DELAY_NANOS);
        }
        pb.finish_and_clear();

        sender_finished_sending_time.swap(true, Ordering::Relaxed);
    });
    // Wait for all sender threads to complete
    // for handle in sender_handles {a
    //     handle.join().unwrap();
    // }
    sender_handle.join().unwrap();
    receiver_handle.join().unwrap();

    let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    Ok(results)
}

fn send_ping(target: IpAddr, identifier: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Create a transport channel
    let (mut tx, _) = transport_channel(
        64,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;

    // Create an ICMP packet
    let mut vec = vec![0; 8];
    let mut echo_packet = MutableEchoRequestPacket::new(&mut vec[..]).unwrap();

    // Fill in the ICMP packet details
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_sequence_number(identifier);

    let checksum = checksum(echo_packet.packet(), 1);
    echo_packet.set_checksum(checksum);

    // Send the ICMP packet
    tx.send_to(echo_packet, target)?;

    Ok(())
}
