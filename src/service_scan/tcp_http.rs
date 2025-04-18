use std::{io::Read, net::IpAddr, time::Duration};

use reqwest::redirect::Policy;

pub fn scan(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();
    let _ = reqwest::blocking::Client::builder()
        .redirect(Policy::none())
        .timeout(timeout)
        .build()
        .unwrap()
        .get(format!("http://{}:{}", ip.to_string(), port))
        .send()?
        .read_to_string(&mut result);

    Ok(result)
}
