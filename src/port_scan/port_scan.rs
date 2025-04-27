use std::net::IpAddr;

use crate::database::DatabaseResult;

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub ip: IpAddr,
    pub open_ports: Vec<i32>,
}

impl PortScanResult {
    pub fn new(ip: IpAddr) -> Self {
        PortScanResult {
            ip,
            open_ports: Vec::new(),
            // data: HashMap::new(),
        }
    }
    // pub fn to_database(&self) -> DatabaseResult {
    //     DatabaseResult {
    //         ip: self.ip.to_string(),
    //         ports: (*self.open_ports).to_vec(),
    //         services: Vec::new(),
    //         responses: String::new(),
    //     }
    // }
}
