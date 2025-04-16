use std::{net::IpAddr, time::Duration};

// Structure to hold ping results
#[derive(Debug)]
pub struct PingResult {
    pub host: IpAddr,
    pub is_up: bool,
    pub response_time: Option<Duration>,
}

impl PingResult {
    pub fn create(addr: IpAddr) -> Self {
        Self {
            host: addr,
            is_up: false,
            response_time: None,
        }
    }
}
