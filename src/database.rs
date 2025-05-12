use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use rand::seq::IteratorRandom;
use regex::Regex;
use rocksdb::{Cache, ColumnFamily, DB, IteratorMode, Options, WriteBatch};
use serde::{Deserialize, Serialize};

use rayon::prelude::*;

// Global settings for optimal performance
const BLOCK_CACHE_SIZE_MB: usize = 512; // 512MB block cache
const WRITE_BUFFER_SIZE_MB: usize = 64; // 64MB write buffer
const NUM_PARALLEL_THREADS: usize = 8; // Number of threads for parallel operations
const BATCH_SIZE: usize = 1000; // Batch size for writes
pub const EPOCH_2025: u32 = 1735689600; // So i don't have to use u64

pub struct ResultDatabase {
    pub path: String,
    options: Options,
    columns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseResult {
    pub ip: String,
    pub port: u16,
    pub time_scanned: u32,

    pub version: String,
    pub protocol: u32,
    pub max_players: u32,
    pub online_players: u32,
    pub players_list: Option<Vec<(String, String)>>,
    pub description: String,
    pub icon_hash: String,

    pub mod_info: Option<(String, Vec<(String, String)>)>,
    pub forge_data: Option<(Vec<(String, String, bool)>, Vec<(String, String)>, i32)>,

    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,
}

pub struct MCResult {}

impl DatabaseResult {
    pub fn to_string(&self) -> String {
        let mut str = "".to_string();

        str += format!(
            "\n{}:{}\n- Last scanned: {}\n- version: [{}]\n- protocol: [{}]\n- max_players: [{}]\n- online_players: [{}]\n- players_list: [{:?}]\n- description: [{}]\n- icon_hash: [{}]\n- mod_info: [{:?}]\n- forge_data: [{:?}]\n- enforces_secure_chat: [{:?}]\n- previews_chat: [{:?}]",
            self.ip,
            self.port,
            DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs((self.time_scanned + EPOCH_2025) as u64)).format("%Y-%m-%d %H:%M:%S.%f").to_string(),
            self.version,
            self.protocol,
            self.max_players,
            self.online_players,
            self.players_list,
            self.description,
            self.icon_hash,
            self.mod_info,
            self.forge_data,
            self.enforces_secure_chat,
            self.previews_chat,
        )
        .as_str();

        str
    }
    pub fn get_addr(&self) -> String {
        format!("{}:{}", self.ip, &self.port)
    }
    pub fn decode_players_list(data: String) -> Option<Vec<(String, String)>> {
        let value = serde_json::to_value(data).unwrap();

        // value.as_array().unwrap().iter().map(|a| a.t).collect()
        Some(vec![(value.to_string(), "".to_string())])
    }
    pub fn decode_mod_info(data: String) -> Option<(String, Vec<(String, String)>)> {
        let value = serde_json::to_value(data).unwrap();

        // value.as_array().unwrap().iter().map(|a| a.t).collect()
        Some(("".to_string(), vec![(value.to_string(), "".to_string())]))
    }
    pub fn decode_forge_data(
        data: String,
    ) -> Option<(Vec<(String, String, bool)>, Vec<(String, String)>, i32)> {
        let value = serde_json::to_value(data).unwrap();

        // value.as_array().unwrap().iter().map(|a| a.t).collect()
        Some((
            vec![(value.to_string(), "".to_string(), false)],
            vec![("".to_string(), "".to_string())],
            5,
        ))
    }
    pub fn decode_option_bool(data: String) -> Option<bool> {
        if data == "true" {
            return Some(true);
        } else if data == "false" {
            return Some(false);
        }
        None
    }
}

pub fn join_nums(nums: &Vec<i32>, sep: &str) -> String {
    // 1. Convert numbers to strings
    let str_nums: Vec<String> = nums
        .iter()
        .map(|n| n.to_string()) // map every integer to a string
        .collect(); // collect the strings into the vector

    // 2. Join the strings. There's already a function for this.
    str_nums.join(sep)
}

pub fn split_nums(str: &str, sep: &str) -> Vec<i32> {
    if str.is_empty() {
        return vec![];
    };

    return str
        .split(sep)
        .map(|n| {
            if let Ok(num) = n.parse::<i32>() {
                return num;
            } else {
                return 0;
            }
        })
        .collect();
}

impl ResultDatabase {
    pub fn new(path: &str) -> Self {
        let mut options = Options::default();

        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.increase_parallelism(NUM_PARALLEL_THREADS as i32); // Use multiple background threads
        options.set_max_background_jobs(4);
        options.set_write_buffer_size(WRITE_BUFFER_SIZE_MB * 1024 * 1024); // Larger write buffer
        options.set_max_write_buffer_number(3); // Allow more write buffers
        options.set_target_file_size_base(64 * 1024 * 1024); // 64MB per SST file
        options.set_level_zero_file_num_compaction_trigger(4); // Start compaction after 4 L0 files
        options.set_level_zero_slowdown_writes_trigger(16); // Start slowing down writes after 16 L0 files
        options.set_level_zero_stop_writes_trigger(24); // Stop writes after 24 L0 files
        options.set_max_bytes_for_level_base(512 * 1024 * 1024); // 512MB for base level
        options.set_disable_auto_compactions(false); // Enable auto compactions
        options.optimize_level_style_compaction(WRITE_BUFFER_SIZE_MB * 1024 * 1024);
        options.set_max_total_wal_size(256 * 1024 * 1024); // 256MB max for WAL files
        options.set_keep_log_file_num(5); // Keep 5 log files
        options.set_log_level(rocksdb::LogLevel::Warn); // Minimal logging

        // Set up block cache for improved read performance
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_block_cache(&Cache::new_lru_cache(BLOCK_CACHE_SIZE_MB * 1024 * 1024));
        block_opts.set_bloom_filter(10.0, false);
        block_opts.set_whole_key_filtering(true);
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        options.set_block_based_table_factory(&block_opts);

        // Define column families for different indexes

        let column_families = vec![
            "addr".to_string(),
            "time".to_string(),
            "version".to_string(),
            "protocol".to_string(),
            "max_players".to_string(),
            "online_players".to_string(),
            "players_list".to_string(),
            "description".to_string(),
            "icon_hash".to_string(),
            "mod_info".to_string(),
            "forge_data".to_string(),
            "enforces_secure_chat".to_string(),
            "previews_chat".to_string(),
        ];

        Self {
            path: path.to_string(),
            options,
            columns: column_families,
        }
    }

    // pub fn add_ping_results(
    //     &self,
    //     results: &Vec<IpAddr>,
    // ) -> Result<(), Box<dyn std::error::Error>> {
    //     let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

    //     for result in results {
    //         string_rows.push(DatabaseResult {
    //             ip: result.to_string(),
    //             ports: vec![],
    //             pub version: String,
    //             pub protocol: i32,
    //             pub max_players: usize,
    //             pub online_players: usize,
    //             pub players_list: Option<Vec<(String, String)>>,
    //             pub description: String,
    //             pub icon_hash: String,

    //             pub mod_info: Option<Vec<(String, String, String)>>,
    //             pub forge_data: Option<(Vec<(String, String, bool)>, Vec<(String, String)>, i32)>,

    //             pub enforces_secure_chat: Option<bool>,
    //             pub previews_chat: Option<bool>,
    //         });
    //     }

    //     return self.save_rows(string_rows);
    // }

    // pub fn add_tcp_results(
    //     &self,
    //     results: &Vec<PortScanResult>,
    // ) -> Result<(), Box<dyn std::error::Error>> {
    //     let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

    //     for result in results {
    //         string_rows.push(result.to_database());
    //     }

    //     return self.save_rows(string_rows);
    // }

    pub fn add_data_row(
        &self,
        results: Vec<DatabaseResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

        for result in results {
            string_rows.push(result);
        }

        return self.save_rows(string_rows);
    }

    pub fn save_rows(
        &self,
        string_rows: Vec<DatabaseResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);

        let cf_addr = db.cf_handle(&self.columns[0]).unwrap();
        let cf_time = db.cf_handle(&self.columns[1]).unwrap();
        let cf_version = db.cf_handle(&self.columns[2]).unwrap();
        let cf_protocol = db.cf_handle(&self.columns[3]).unwrap();
        let cf_max_players = db.cf_handle(&self.columns[4]).unwrap();
        let cf_online_players = db.cf_handle(&self.columns[5]).unwrap();
        let cf_players_list = db.cf_handle(&self.columns[6]).unwrap();
        let cf_description = db.cf_handle(&self.columns[7]).unwrap();
        let cf_icon_hash = db.cf_handle(&self.columns[8]).unwrap();
        let cf_mod_info = db.cf_handle(&self.columns[9]).unwrap();
        let cf_forge_data = db.cf_handle(&self.columns[10]).unwrap();
        let cf_enforces_secure_chat = db.cf_handle(&self.columns[11]).unwrap();
        let cf_previews_chat = db.cf_handle(&self.columns[12]).unwrap();

        let start = Instant::now();
        let length = string_rows.len();

        // Split the rows into chunks for parallel processing
        let chunks: Vec<Vec<DatabaseResult>> = string_rows
            .chunks(BATCH_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect();

        // Process chunks in parallel
        let elapsed = {
            let db_ref = Arc::clone(&db);

            // Create batches in parallel but write them sequentially
            let batches: Vec<WriteBatch> = chunks
                .into_iter()
                .map(|chunk| {
                    let mut batch = WriteBatch::default();

                    for row in chunk {
                        let key = row.get_addr();
                        println!("{}", key);
                        let key = key.as_bytes();

                        batch.put_cf(cf_addr, key, key);
                        batch.put_cf(cf_time, key, row.time_scanned.to_string().as_bytes());
                        batch.put_cf(cf_version, key, row.version.as_bytes());
                        batch.put_cf(cf_protocol, key, row.protocol.to_string().as_bytes());
                        batch.put_cf(cf_max_players, key, row.max_players.to_string().as_bytes());
                        batch.put_cf(
                            cf_online_players,
                            key,
                            row.online_players.to_string().as_bytes(),
                        );
                        batch.put_cf(
                            cf_players_list,
                            key,
                            serde_json::to_string(&row.players_list).unwrap().as_bytes(),
                        );
                        batch.put_cf(
                            cf_players_list,
                            key,
                            serde_json::to_string(&row.players_list).unwrap().as_bytes(),
                        );
                        batch.put_cf(cf_description, key, row.description.as_bytes());
                        batch.put_cf(cf_icon_hash, key, row.icon_hash.as_bytes());
                        batch.put_cf(
                            cf_mod_info,
                            key,
                            serde_json::to_string(&row.mod_info).unwrap().as_bytes(),
                        );
                        batch.put_cf(
                            cf_forge_data,
                            key,
                            serde_json::to_string(&row.forge_data).unwrap().as_bytes(),
                        );
                        batch.put_cf(
                            cf_enforces_secure_chat,
                            key,
                            serde_json::to_string(&row.enforces_secure_chat)
                                .unwrap()
                                .as_bytes(),
                        );
                        batch.put_cf(
                            cf_previews_chat,
                            key,
                            serde_json::to_string(&row.previews_chat)
                                .unwrap()
                                .as_bytes(),
                        );
                    }

                    batch
                })
                .collect();

            // Write all batches to the database
            for batch in batches {
                db_ref.write(batch)?;
            }

            // Force a flush to ensure all data is persisted
            db_ref.flush()?;

            start.elapsed()
        };

        println!("Saved {} rows in {}ms", length, elapsed.as_millis());

        Ok(())
    }

    pub fn get_row_by_host(&self, row: &str) -> Option<DatabaseResult> {
        let db = DB::open_cf(&self.options, &self.path, &self.columns);
        if db.is_err() {
            return None;
        };
        let db = db.unwrap();

        let cfs = vec![
            db.cf_handle(&self.columns[0]).unwrap(),
            db.cf_handle(&self.columns[1]).unwrap(),
            db.cf_handle(&self.columns[2]).unwrap(),
            db.cf_handle(&self.columns[3]).unwrap(),
            db.cf_handle(&self.columns[4]).unwrap(),
            db.cf_handle(&self.columns[5]).unwrap(),
            db.cf_handle(&self.columns[6]).unwrap(),
            db.cf_handle(&self.columns[7]).unwrap(),
            db.cf_handle(&self.columns[8]).unwrap(),
            db.cf_handle(&self.columns[9]).unwrap(),
            db.cf_handle(&self.columns[10]).unwrap(),
            db.cf_handle(&self.columns[11]).unwrap(),
            db.cf_handle(&self.columns[12]).unwrap(),
        ];

        return self.fetch_row(&db, row, &cfs);
    }

    pub fn get_rows_by_port(&self, port: &str) -> Vec<DatabaseResult> {
        if let Ok(result) = self.search_substring_in_column_regex(
            self.columns[1].as_str(),
            Regex::new(&format!(r"\b{}\b", port)).unwrap(),
        ) {
            return result;
        } else {
            return Vec::new();
        }
    }

    pub fn get_rows_by_service(&self, service: &str) -> Vec<DatabaseResult> {
        if let Ok(result) = self.search_substring_in_column(self.columns[2].as_str(), service) {
            return result;
        } else {
            return Vec::new();
        }
    }

    pub fn search_substring_in_column(
        &self,
        column: &str,
        string: &str,
    ) -> Result<Vec<DatabaseResult>, rocksdb::Error> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);

        let cf = db.cf_handle(column).unwrap();
        let cfs = vec![
            db.cf_handle(&self.columns[0]).unwrap(),
            db.cf_handle(&self.columns[1]).unwrap(),
            db.cf_handle(&self.columns[2]).unwrap(),
            db.cf_handle(&self.columns[3]).unwrap(),
            db.cf_handle(&self.columns[4]).unwrap(),
            db.cf_handle(&self.columns[5]).unwrap(),
            db.cf_handle(&self.columns[6]).unwrap(),
            db.cf_handle(&self.columns[7]).unwrap(),
            db.cf_handle(&self.columns[8]).unwrap(),
            db.cf_handle(&self.columns[9]).unwrap(),
            db.cf_handle(&self.columns[10]).unwrap(),
            db.cf_handle(&self.columns[11]).unwrap(),
            db.cf_handle(&self.columns[12]).unwrap(),
        ];

        let mut matching_keys: Vec<DatabaseResult> = Vec::new();

        let iter = db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(value_str) = std::str::from_utf8(&value_bytes) {
                // Check if the value contains the substring
                if value_str.contains(string) {
                    // Convert key to string and add to results
                    if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                        if let Some(row) = self.fetch_row(&db, key_str, &cfs) {
                            matching_keys.push(row);
                        }
                    }
                }
            }
        }

        Ok(matching_keys)
    }

    pub fn get_random_result(&self) -> Result<DatabaseResult, rocksdb::Error> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);
        let cfs = vec![
            db.cf_handle(&self.columns[0]).unwrap(),
            db.cf_handle(&self.columns[1]).unwrap(),
            db.cf_handle(&self.columns[2]).unwrap(),
            db.cf_handle(&self.columns[3]).unwrap(),
            db.cf_handle(&self.columns[4]).unwrap(),
            db.cf_handle(&self.columns[5]).unwrap(),
            db.cf_handle(&self.columns[6]).unwrap(),
            db.cf_handle(&self.columns[7]).unwrap(),
            db.cf_handle(&self.columns[8]).unwrap(),
            db.cf_handle(&self.columns[9]).unwrap(),
            db.cf_handle(&self.columns[10]).unwrap(),
            db.cf_handle(&self.columns[11]).unwrap(),
            db.cf_handle(&self.columns[12]).unwrap(),
        ];

        let iter = db.iterator_cf(cfs[0], IteratorMode::Start);
        let (key_bytes, _value_bytes) = iter
            .choose(&mut rand::rng())
            .expect("Failed to aquire random")
            .expect("Failed to aquire random");

        let key_str = std::str::from_utf8(&key_bytes).expect("Failed to parse key str");
        let row = self
            .fetch_row(&db, key_str, &cfs)
            .expect("Failed to fetch row");

        Ok(row)
    }

    pub fn search_substring_in_column_regex(
        &self,
        column: &str,
        regex: Regex,
    ) -> Result<Vec<DatabaseResult>, rocksdb::Error> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);

        let cf = db.cf_handle(column).unwrap();
        let cfs = vec![
            db.cf_handle(&self.columns[0]).unwrap(),
            db.cf_handle(&self.columns[1]).unwrap(),
            db.cf_handle(&self.columns[2]).unwrap(),
            db.cf_handle(&self.columns[3]).unwrap(),
            db.cf_handle(&self.columns[4]).unwrap(),
            db.cf_handle(&self.columns[5]).unwrap(),
            db.cf_handle(&self.columns[6]).unwrap(),
            db.cf_handle(&self.columns[7]).unwrap(),
            db.cf_handle(&self.columns[8]).unwrap(),
            db.cf_handle(&self.columns[9]).unwrap(),
            db.cf_handle(&self.columns[10]).unwrap(),
            db.cf_handle(&self.columns[11]).unwrap(),
            db.cf_handle(&self.columns[12]).unwrap(),
        ];

        let mut matching_keys: Vec<DatabaseResult> = Vec::new();

        let iter = db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key_bytes, value_bytes) = item?;
            if let Ok(value_str) = std::str::from_utf8(&value_bytes) {
                // Check if the value contains the substring
                if regex.is_match(value_str) {
                    // Convert key to string and add to results
                    if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                        if let Some(row) = self.fetch_row(&db, key_str, &cfs) {
                            matching_keys.push(row);
                        }
                    }
                }
            }
        }

        Ok(matching_keys)
    }

    pub fn search(
        &self,
        queries: Vec<QueryDataType>,
    ) -> Result<Vec<DatabaseResult>, rocksdb::Error> {
        if queries.len() == 0 {
            return Ok(Vec::new());
        }
        if queries.len() == 1 {
            // Return host if results include host
            match queries[0] {
                QueryDataType::Addr(row, port) => {
                    return Ok(vec![
                        self.get_row_by_host(
                            format!("{}:{}", row.to_string().as_str(), port).as_str(),
                        )
                        .expect("Host Not Found"),
                    ]);
                }
                _ => {}
            }
        }

        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);

        let cfs = vec![
            db.cf_handle(&self.columns[0]).unwrap(),
            db.cf_handle(&self.columns[1]).unwrap(),
            db.cf_handle(&self.columns[2]).unwrap(),
            db.cf_handle(&self.columns[3]).unwrap(),
            db.cf_handle(&self.columns[4]).unwrap(),
            db.cf_handle(&self.columns[5]).unwrap(),
            db.cf_handle(&self.columns[6]).unwrap(),
            db.cf_handle(&self.columns[7]).unwrap(),
            db.cf_handle(&self.columns[8]).unwrap(),
            db.cf_handle(&self.columns[9]).unwrap(),
            db.cf_handle(&self.columns[10]).unwrap(),
            db.cf_handle(&self.columns[11]).unwrap(),
            db.cf_handle(&self.columns[12]).unwrap(),
        ];

        let matching_key_bytes = search_parallel(&db, queries, &cfs);
        let mut matching_rows = Vec::new();

        for key_bytes in matching_key_bytes {
            if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                if let Some(row) = self.fetch_row(&db, &key_str, &cfs) {
                    matching_rows.push(row);
                }
            }
        }

        Ok(matching_rows)
    }

    fn fetch_row(&self, db: &DB, row_id: &str, cfs: &Vec<&ColumnFamily>) -> Option<DatabaseResult> {
        match db.get_cf(&cfs[0], row_id.as_bytes()) {
            Ok(Some(_)) => Some(DatabaseResult {
                ip: row_id.to_string().split(":").nth(0).unwrap().to_string(),
                port: row_id
                    .to_string()
                    .split(":")
                    .nth(1)
                    .unwrap()
                    .to_string()
                    .parse::<u16>()
                    .unwrap(),
                time_scanned: self
                    .row_to_string(db, row_id, &cfs[1])
                    .parse::<u32>()
                    .unwrap(),
                version: self.row_to_string(db, row_id, &cfs[2]),
                protocol: self
                    .row_to_string(db, row_id, &cfs[3])
                    .parse::<u32>()
                    .unwrap(),
                max_players: self
                    .row_to_string(db, row_id, &cfs[4])
                    .parse::<u32>()
                    .unwrap(),
                online_players: self
                    .row_to_string(db, row_id, &cfs[5])
                    .parse::<u32>()
                    .unwrap(),
                players_list: DatabaseResult::decode_players_list(
                    self.row_to_string(db, row_id, &cfs[6]),
                ),
                description: self.row_to_string(db, row_id, &cfs[7]),
                icon_hash: self.row_to_string(db, row_id, &cfs[8]),
                mod_info: DatabaseResult::decode_mod_info(self.row_to_string(db, row_id, &cfs[9])),
                forge_data: DatabaseResult::decode_forge_data(
                    self.row_to_string(db, row_id, &cfs[10]),
                ),
                enforces_secure_chat: DatabaseResult::decode_option_bool(
                    self.row_to_string(db, row_id, &cfs[11]),
                ),
                previews_chat: DatabaseResult::decode_option_bool(
                    self.row_to_string(db, row_id, &cfs[12]),
                ),
            }),
            _ => None,
        }
    }

    fn row_to_string(&self, db: &DB, row_id: &str, cf: &ColumnFamily) -> String {
        if let Ok(Some(data)) = db.get_cf(cf, row_id) {
            String::from_utf8_lossy(&*data).to_string()
        } else {
            String::new()
        }
    }
}

#[derive(Debug)]
pub enum QueryDataType {
    Addr(IpAddr, u16),
    Host(QueryType, String),
    Port(QueryType, u32),
    ScanTime(QueryType, u32),
    Version(QueryType, String),
    Protocol(QueryType, u32),
    MaxPlayers(QueryType, u32),
    OnlinePlayers(QueryType, u32),
    PlayersList(QueryType, String),
    Description(QueryType, String),
    IconHash(QueryType, String),
    ModInfo(QueryType, String),
    ForgeData(QueryType, String),
    SecureChat(QueryType, String),
    PreviewsChat(QueryType, String),
}

#[derive(Debug)]
pub enum QueryType {
    Equals,

    NotEquals,
    Includes,
    NotIncludes,

    GreaterThan,
    LessThan,

    GreaterOrEqual,
    LessThanOrEqual,
}

// /// Search function that takes query constraints and returns matching keys
// pub fn search(db: &DB, queries: Vec<QueryDataType>) -> Vec<Vec<u8>> {
//     // Get column family handles
//     let cf_ports = db
//         .cf_handle("ports")
//         .expect("Column family 'ports' not found");
//     let cf_services = db
//         .cf_handle("services")
//         .expect("Column family 'services' not found");
//     let cf_responses = db
//         .cf_handle("responses")
//         .expect("Column family 'responses' not found");

//     // Prepare search results
//     let mut matching_keys = Vec::new();
//     let mut potential_keys = collect_all_keys(db, cf_ports);

//     // Partition queries by type to optimize processing
//     let mut port_queries = Vec::new();
//     let mut service_queries = Vec::new();
//     let mut fulltext_queries = Vec::new();

//     for query in queries {
//         match query {
//             QueryDataType::Port(_, _) => port_queries.push(query),
//             QueryDataType::Service(_, _, _) => service_queries.push(query),
//             QueryDataType::FullTextIncludes(_) => fulltext_queries.push(query),
//             _ => {}
//         }
//     }

//     // Apply port queries first (typically most restrictive)
//     if !port_queries.is_empty() {
//         potential_keys = filter_by_port_queries(db, cf_ports, potential_keys, &port_queries);
//     }

//     // Apply service queries
//     if !service_queries.is_empty() {
//         potential_keys =
//             filter_by_service_queries(db, cf_services, potential_keys, &service_queries);
//     }

//     // Apply fulltext queries last (typically most expensive)
//     if !fulltext_queries.is_empty() {
//         potential_keys =
//             filter_by_fulltext_queries(db, cf_responses, potential_keys, &fulltext_queries);
//     }

//     matching_keys = potential_keys;
//     matching_keys
// }

fn collect_all_keys(db: &DB, cf: &ColumnFamily) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);

    for result in iter {
        if let Ok((key, _)) = result {
            keys.push(key.to_vec());
        }
    }

    keys
}

pub fn search_parallel(
    db: &DB,
    queries: Vec<QueryDataType>,
    cfs: &Vec<&ColumnFamily>,
) -> Vec<Vec<u8>> {
    // Get column family handles
    let cf_addr = cfs[0];
    let cf_scan_time = cfs[1];
    let cf_version = cfs[2];
    let cf_protocol = cfs[3];
    let cf_max_players = cfs[4];
    let cf_online_players = cfs[5];
    let cf_players_list = cfs[6];
    let cf_description = cfs[7];
    let cf_icon_hash = cfs[8];
    let cf_mod_info = cfs[9];
    let cf_forge_data = cfs[10];
    let cf_secure_chat = cfs[11];
    let cf_previews_chat = cfs[12];

    // Partition queries by type
    let mut host_queries = Vec::new();
    let mut port_queries = Vec::new();

    let mut time_queries = Vec::new();
    let mut version_queries = Vec::new();
    let mut protocol_queries = Vec::new();
    let mut max_players_queries = Vec::new();
    let mut online_players_queries = Vec::new();
    let mut players_list_queries = Vec::new();
    let mut description_queries = Vec::new();
    let mut icon_hash_queries = Vec::new();
    let mut mod_info_queries = Vec::new();
    let mut forge_data_queries = Vec::new();
    let mut secure_chat_queries = Vec::new();
    let mut previews_chat_queries = Vec::new();

    for q in queries {
        match q {
            QueryDataType::Host(_, _) => host_queries.push(q),
            QueryDataType::Port(_, _) => port_queries.push(q),
            QueryDataType::ScanTime(_, _) => time_queries.push(q),
            QueryDataType::Version(_, _) => version_queries.push(q),
            QueryDataType::Protocol(_, _) => protocol_queries.push(q),
            QueryDataType::MaxPlayers(_, _) => max_players_queries.push(q),
            QueryDataType::OnlinePlayers(_, _) => online_players_queries.push(q),
            QueryDataType::PlayersList(_, _) => players_list_queries.push(q),
            QueryDataType::Description(_, _) => description_queries.push(q),
            QueryDataType::IconHash(_, _) => icon_hash_queries.push(q),
            QueryDataType::ModInfo(_, _) => mod_info_queries.push(q),
            QueryDataType::ForgeData(_, _) => forge_data_queries.push(q),
            QueryDataType::SecureChat(_, _) => secure_chat_queries.push(q),
            QueryDataType::PreviewsChat(_, _) => previews_chat_queries.push(q),

            _ => {} // This should never happen
        }
    }

    fn match_string_comparison(qt: &QueryType, test: &str, data: &str) -> bool {
        match qt {
            QueryType::Equals => data == test,
            QueryType::NotEquals => data != test,
            QueryType::Includes => data.contains(test),
            QueryType::NotIncludes => !data.contains(test),
            _ => false,
        }
    }

    fn match_num_comparison(qt: &QueryType, test: &u32, data: &str) -> bool {
        if let Ok(data) = data.parse::<u32>() {
            match qt {
                QueryType::Equals => &data == test,
                QueryType::NotEquals => &data != test,
                QueryType::GreaterThan => &data > test,
                QueryType::LessThan => &data < test,
                QueryType::GreaterOrEqual => &data >= test,
                QueryType::LessThanOrEqual => &data <= test,
                _ => false,
            }
        } else {
            false
        }
    }

    fn loop_queries(
        db: &DB,
        cf: &ColumnFamily,
        key: &Vec<u8>,
        queries: &Vec<QueryDataType>,
    ) -> bool {
        if let Ok(bytes) = db.get_cf(cf, key) {
            if let Some(bytes) = bytes {
                if let Ok(data) = std::str::from_utf8(&bytes) {
                    queries.iter().all(|query| match query {
                        QueryDataType::Addr(_, _) => false,
                        QueryDataType::Host(qt, test) => {
                            match_string_comparison(qt, test, data.split(":").nth(0).unwrap_or(""))
                        }
                        QueryDataType::Port(qt, test) => {
                            match_num_comparison(qt, test, data.split(":").nth(1).unwrap_or(""))
                        }
                        QueryDataType::ScanTime(qt, test) => match_num_comparison(qt, test, data),
                        QueryDataType::Version(qt, test) => match_string_comparison(qt, test, data),
                        QueryDataType::Protocol(qt, test) => match_num_comparison(qt, test, data),
                        QueryDataType::MaxPlayers(qt, test) => match_num_comparison(qt, test, data),
                        QueryDataType::OnlinePlayers(qt, test) => {
                            match_num_comparison(qt, test, data)
                        }
                        QueryDataType::PlayersList(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                        QueryDataType::Description(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                        QueryDataType::IconHash(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                        QueryDataType::ModInfo(qt, test) => match_string_comparison(qt, test, data),
                        QueryDataType::ForgeData(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                        QueryDataType::SecureChat(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                        QueryDataType::PreviewsChat(qt, test) => {
                            match_string_comparison(qt, test, data)
                        }
                    })
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    // Process in parallel using rayon
    let matching_keys: Vec<Vec<u8>> = collect_all_keys(db, cf_addr)
        .into_par_iter()
        .filter(|key| {
            // Check port queries
            (host_queries.is_empty() || loop_queries(db, cf_addr, key, &host_queries))
                && (port_queries.is_empty() || loop_queries(db, cf_addr, key, &port_queries))
                && (time_queries.is_empty() || loop_queries(db, cf_scan_time, key, &time_queries))
                && (version_queries.is_empty()
                    || loop_queries(db, cf_version, key, &version_queries))
                && (protocol_queries.is_empty()
                    || loop_queries(db, cf_protocol, key, &protocol_queries))
                && (max_players_queries.is_empty()
                    || loop_queries(db, cf_max_players, key, &max_players_queries))
                && (online_players_queries.is_empty()
                    || loop_queries(db, cf_online_players, key, &online_players_queries))
                && (players_list_queries.is_empty()
                    || loop_queries(db, cf_players_list, key, &players_list_queries))
                && (description_queries.is_empty()
                    || loop_queries(db, cf_description, key, &description_queries))
                && (icon_hash_queries.is_empty()
                    || loop_queries(db, cf_icon_hash, key, &icon_hash_queries))
                && (mod_info_queries.is_empty()
                    || loop_queries(db, cf_mod_info, key, &mod_info_queries))
                && (forge_data_queries.is_empty()
                    || loop_queries(db, cf_forge_data, key, &forge_data_queries))
                && (secure_chat_queries.is_empty()
                    || loop_queries(db, cf_secure_chat, key, &secure_chat_queries))
                && (previews_chat_queries.is_empty()
                    || loop_queries(db, cf_previews_chat, key, &previews_chat_queries))
        })
        .collect();

    matching_keys
}
