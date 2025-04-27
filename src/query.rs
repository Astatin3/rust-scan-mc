use std::{net::IpAddr, str::FromStr};

use regex::Regex;

use crate::database::{QueryDataType, QueryType, split_nums};

fn try_parse_host(query: &str) -> Option<QueryDataType> {
    if query.contains(":") {
        let mut split = query.split(",");
        let ip = IpAddr::from_str(split.nth(0).unwrap());
        if let Some(port) = &split.nth(1) {
            if let (Ok(ip), Ok(port)) = (ip, port.parse::<u16>()) {
                return Some(QueryDataType::Host(ip, port));
            }
        }
    }
    if let Ok(ip) = IpAddr::from_str(&query) {
        return Some(QueryDataType::Host(ip, 25565));
    }

    None
}

pub fn search(query: String) -> Result<Vec<QueryDataType>, Box<dyn std::error::Error>> {
    if let Some(host) = try_parse_host(&query) {
        return Ok(vec![host]);
    }

    let split = query.split(" ");

    let delim = Regex::new("(?:!=|<=|>=|[=:+-><])")?;

    let mut results = Vec::new();

    for query in split {
        if let Some(host) = try_parse_host(query) {
            return Ok(vec![host]);
        }

        if let Some(m) = delim.find(query) {
            let tag = query[0..m.start()].to_string().to_lowercase();
            let delim = query[m.start()..m.end()].to_string();
            let data = query[m.end()..query.len()].to_string();

            fn get_equals_type_str(delim: &str) -> QueryType {
                match delim {
                    ":" | "+" => Some(QueryType::Includes),
                    "-" => Some(QueryType::NotIncludes),
                    "=" => Some(QueryType::Equals),
                    "!=" => Some(QueryType::NotEquals),
                    _ => None,
                }
                .expect(format!("Strings cannot be determined by \"{}\"", delim).as_str())
            }

            fn get_equals_type_num(delim: &str) -> QueryType {
                match delim {
                    "=" => Some(QueryType::Equals),
                    "!=" => Some(QueryType::NotEquals),
                    ">" => Some(QueryType::GreaterThan),
                    "<" => Some(QueryType::LessThan),
                    ">=" => Some(QueryType::GreaterOrEqual),
                    "<=" => Some(QueryType::LessThanOrEqual),
                    _ => None,
                }
                .expect(format!("Nums cannot be determined by \"{}\"", delim).as_str())
            }

            (match tag.as_str() {
                "version" => {
                    results.push(QueryDataType::Version(get_equals_type_str(&delim), data));
                    Ok(())
                }
                "protocol" => {
                    results.push(QueryDataType::Protocol(
                        get_equals_type_num(&delim),
                        data.parse::<u32>().expect("Error parsing protocol"),
                    ));
                    Ok(())
                }

                "maxplayers" => {
                    results.push(QueryDataType::MaxPlayers(
                        get_equals_type_num(&delim),
                        data.parse::<u32>().expect("Error parsing max players"),
                    ));
                    Ok(())
                }

                "onlineplayers" => {
                    results.push(QueryDataType::OnlinePlayers(
                        get_equals_type_num(&delim),
                        data.parse::<u32>().expect("Error parsing online players"),
                    ));
                    Ok(())
                }

                "playerslist" => {
                    results.push(QueryDataType::PlayersList(
                        get_equals_type_str(&delim),
                        data,
                    ));
                    Ok(())
                }

                "description" => {
                    results.push(QueryDataType::Description(
                        get_equals_type_str(&delim),
                        data,
                    ));
                    Ok(())
                }

                "iconhash" => {
                    results.push(QueryDataType::IconHash(get_equals_type_str(&delim), data));
                    Ok(())
                }

                "modinfo" => {
                    results.push(QueryDataType::ModInfo(get_equals_type_str(&delim), data));
                    Ok(())
                }

                "forgedata" => {
                    results.push(QueryDataType::ForgeData(get_equals_type_str(&delim), data));
                    Ok(())
                }

                "securechat" => {
                    if !vec!["true".to_string(), "false".to_string(), "None".to_string()]
                        .contains(&data)
                    {
                        Err(())
                    } else {
                        results.push(QueryDataType::SecureChat(get_equals_type_str(&delim), data));

                        Ok(())
                    }
                }
                "previewschat" => {
                    if !vec!["true".to_string(), "false".to_string(), "None".to_string()]
                        .contains(&data)
                    {
                        Err(())
                    } else {
                        results.push(QueryDataType::PreviewsChat(
                            get_equals_type_str(&delim),
                            data,
                        ));

                        Ok(())
                    }
                }
                _ => Err(()),
            })
            .expect(format!("Invalid Tag: \"{}\"", tag).as_str());
        }

        // (host, data) =
    }

    for result in &results {
        println!("{:?}", result);
    }

    Ok(results)
}
