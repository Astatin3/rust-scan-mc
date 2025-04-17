use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::database::StringRow;

// Structure to hold ping results
#[derive(Debug, Serialize, Deserialize, Clone)]
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

    pub fn to_string_row(&self) -> StringRow {
        StringRow {
            id: self.host.to_string(),
            ports: vec![],
        }
    }
}
