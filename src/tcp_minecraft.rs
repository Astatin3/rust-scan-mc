use craftping::sync::ping;
use serde_json::json;
use sha256::digest;
use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::database::{DatabaseResult, EPOCH_2025};

pub fn scan(
    ip: IpAddr,
    port: &i32,
    timeout: Duration,
) -> Result<DatabaseResult, Box<dyn std::error::Error>> {
    let port = *port as u16;
    let socket = SocketAddr::new(ip, port);
    let ip = ip.to_string();

    let mut stream = TcpStream::connect_timeout(&socket, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let pong = ping(&mut stream, &ip, port)?;

    let icon_hash = match pong.favicon {
        Some(icon) => digest(icon),
        None => "None".to_string(),
    };

    Ok(DatabaseResult {
        ip: ip.to_string(),
        port: port as u16,
        time_scanned: (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - EPOCH_2025 as u64) as u32,
        version: pong.version,
        protocol: pong.protocol as u32,
        max_players: pong.max_players as u32,
        online_players: pong.online_players as u32,
        players_list: if let Some(sample) = pong.sample {
            Some(
                sample
                    .iter()
                    .map(|a| (a.id.clone(), a.name.clone()))
                    .collect(),
            )
        } else {
            None
        },
        description: pong.description.unwrap_or(json!("")).to_string(),
        icon_hash: icon_hash,
        mod_info: if let Some(mod_info) = pong.mod_info {
            Some((
                mod_info.mod_type,
                mod_info
                    .mod_list
                    .iter()
                    .map(|a| (a.mod_id.clone(), a.version.clone()))
                    .collect(),
            ))
        } else {
            None
        },
        forge_data: if let Some(forge_data) = pong.forge_data {
            Some((
                forge_data
                    .channels
                    .iter()
                    .map(|a| (a.version.clone(), a.res.clone(), a.required))
                    .collect(),
                forge_data
                    .mods
                    .iter()
                    .map(|a| (a.mod_marker.clone(), a.mod_id.clone()))
                    .collect(),
                forge_data.fml_network_version,
            ))
        } else {
            None
        },
        enforces_secure_chat: pong.enforces_secure_chat,
        previews_chat: pong.previews_chat,
    })

    // Ok(serde_json::to_string(&json!({
    //     "version": pong.version,
    //     "protocol": pong.protocol,
    //     "max_players": pong.max_players,
    //     "online_players": pong.online_players,
    //     "players_list": pong.sample,

    //     "description": pong.description,
    //     "icon": icon_hash,

    //     "mod_info": pong.mod_info,
    //     "forge_data": pong.forge_data,

    //     "enforces_secure_chat": pong.enforces_secure_chat,
    //     "previews_chat": pong.previews_chat
    // }))?)
}
