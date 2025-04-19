use craftping::sync::ping;
use serde_json::json;
use sha256::digest;
use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};

pub fn scan(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let port = *port as u16;
    let socket = SocketAddr::new(ip, port);
    let ip = ip.to_string();

    let mut stream = TcpStream::connect_timeout(&socket, timeout)?;
    let pong = ping(&mut stream, &ip, port)?;

    let icon_hash = match pong.favicon {
        Some(icon) => digest(icon),
        None => "null".to_string(),
    };

    Ok(serde_json::to_string(&json!({
        "version": pong.version,
        "protocol": pong.protocol,
        "max_players": pong.max_players,
        "online_players": pong.online_players,
        "players_list": pong.sample,

        "description": pong.description,
        "icon": icon_hash,

        "mod_info": pong.mod_info,
        "forge_data": pong.forge_data,

        "enforces_secure_chat": pong.enforces_secure_chat,
        "previews_chat": pong.previews_chat
    }))?)
}
