use std::{io::Read, net::IpAddr, time::Duration};

use reqwest::redirect::Policy;

pub fn scan(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();

    // println!("https start");

    let mut response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .unwrap()
        .get(format!("https://{}:{}", ip.to_string(), port))
        .send()?;

    // println!("https read");

    let _ = response.read_to_string(&mut result);

    // println!("https stop");

    // println!("{}", result);

    Ok(result)
}
