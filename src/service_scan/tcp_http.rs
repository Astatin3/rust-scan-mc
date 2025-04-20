use std::{io::Read, net::IpAddr, time::Duration};

use reqwest::redirect::Policy;

pub fn scan(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();

    // println!("HTTP start");

    let mut r = reqwest::blocking::Client::builder()
        .redirect(Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .unwrap()
        .get(format!("http://{}:{}", ip.to_string(), port))
        .send()?;

    // println!("HTTP reading");

    let _ = r.read_to_string(&mut result)?;

    // println!("HTTP stop");

    Ok(result)
}
