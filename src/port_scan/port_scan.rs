use std::net::IpAddr;

use crate::database::StringRow;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub open_ports: Vec<i32>,
    // pub data: HashMap<i32, Vec<u8>>,
}

impl ScanResult {
    pub fn new(ip: IpAddr) -> Self {
        ScanResult {
            ip,
            open_ports: Vec::new(),
            // data: HashMap::new(),
        }
    }
    pub fn to_string_row(&self) -> StringRow {
        StringRow {
            id: self.ip.to_string(),
            ports: (*self.open_ports).to_vec(),
        }
    }
}
