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
            values: vec![join_nums(&self.open_ports, ",")],
        }
    }
}

fn join_nums(nums: &Vec<i32>, sep: &str) -> String {
    // 1. Convert numbers to strings
    let str_nums: Vec<String> = nums
        .iter()
        .map(|n| n.to_string()) // map every integer to a string
        .collect(); // collect the strings into the vector

    // 2. Join the strings. There's already a function for this.
    str_nums.join(sep)
}
