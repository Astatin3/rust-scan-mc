use std::{net::IpAddr, str::FromStr};

use regex::Regex;

use crate::database::{QueryDataType, QueryType, split_nums};

pub fn search(query: String) -> Result<Vec<QueryDataType>, Box<dyn std::error::Error>> {
    if let Ok(ip) = IpAddr::from_str(&query) {
        return Ok(vec![QueryDataType::Host(ip)]);
    }

    let split = query.split(" ");

    let delim = Regex::new("(?:!=|[=:;])")?;

    let mut results = Vec::new();

    for query in split {
        if let Ok(ip) = IpAddr::from_str(&query) {
            return Ok(vec![QueryDataType::Host(ip)]);
        }

        if let Some(m) = delim.find(query) {
            let tag = query[0..m.start()].to_string();
            let delim = query[m.start()..m.end()].to_string();
            let data = query[m.end()..query.len()].to_string();

            fn get_equals_type(delim: &str) -> QueryType {
                match delim {
                    ":" => Some(QueryType::Includes),
                    ";" => Some(QueryType::NotIncludes),
                    "=" => Some(QueryType::Equals),
                    "!=" => Some(QueryType::NotEquals),
                    _ => None,
                }
                .expect("Error parsing query")
            }

            match tag.as_str() {
                "port" => {
                    let mut ports = split_nums(&data, ",");

                    ports.sort();
                    ports.dedup();

                    for port in ports {
                        if port == 0 {
                            continue;
                        }
                        results.push(QueryDataType::Port(get_equals_type(&delim), port));
                    }
                }
                _ => results.push(QueryDataType::Service(get_equals_type(&delim), tag, data)),
            };
        } else {
            results.push(QueryDataType::FullTextIncludes(query.to_string()));
        }

        // (host, data) =
    }

    for result in &results {
        println!("{:?}", result);
    }

    Ok(results)
}
