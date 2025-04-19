use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};

use regex::Regex;
use rocksdb::{Cache, ColumnFamily, DB, IteratorMode, Options, WriteBatch};
use serde::{Deserialize, Serialize};

use rayon::prelude::*;

use crate::{port_scan::port_scan::PortScanResult, service_scan::service_scan::ServiceScanResult};

// Global settings for optimal performance
const BLOCK_CACHE_SIZE_MB: usize = 512; // 512MB block cache
const WRITE_BUFFER_SIZE_MB: usize = 64; // 64MB write buffer
const NUM_PARALLEL_THREADS: usize = 8; // Number of threads for parallel operations
const BATCH_SIZE: usize = 1000; // Batch size for writes

pub struct ResultDatabase {
    pub path: String,
    options: Options,
    columns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseResult {
    pub id: String,
    pub ports: Vec<i32>,
    pub services: Vec<String>,
    pub responses: String,
}

impl DatabaseResult {
    pub fn to_string(&self) -> String {
        let mut str = "".to_string();

        str += format!(
            "\n{}\n- ports: [{}]\n- services: [{}]\n- responses: [{}]",
            self.id,
            join_nums(&self.ports, ","),
            self.services.join(", "),
            if let Ok(data) =
                serde_json::from_str::<HashMap<i32, (String, String)>>(self.responses.as_str())
            {
                format!("{:?}", data)
            } else {
                self.responses.clone()
            }
        )
        .as_str();

        str
    }
    pub fn ports_to_string(&self) -> String {
        return join_nums(&self.ports, ",");
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
            "default".to_string(),
            "ports".to_string(),
            "services".to_string(),
            "responses".to_string(),
        ];

        Self {
            path: path.to_string(),
            options,
            columns: column_families,
        }
    }

    pub fn add_ping_results(
        &self,
        results: &Vec<IpAddr>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

        for result in results {
            string_rows.push(DatabaseResult {
                id: result.to_string(),
                ports: vec![],
                services: Vec::new(),
                responses: String::new(),
            });
        }

        return self.save_rows(string_rows);
    }

    pub fn add_tcp_results(
        &self,
        results: &Vec<PortScanResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

        for result in results {
            string_rows.push(result.to_database());
        }

        return self.save_rows(string_rows);
    }

    pub fn add_service_results(
        &self,
        results: &Vec<ServiceScanResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

        for result in results {
            string_rows.push(result.to_database());
        }

        return self.save_rows(string_rows);
    }

    pub fn save_rows(
        &self,
        string_rows: Vec<DatabaseResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);
        let cf_default = db.cf_handle(&self.columns[0]).unwrap();
        let cf_ports = db.cf_handle(&self.columns[1]).unwrap();
        let cf_services = db.cf_handle(&self.columns[2]).unwrap();
        let cf_responses = db.cf_handle(&self.columns[3]).unwrap();

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
            let cf_default_ref = cf_default;

            // Create batches in parallel but write them sequentially
            let batches: Vec<WriteBatch> = chunks
                .into_iter()
                .map(|chunk| {
                    let mut batch = WriteBatch::default();

                    for row in chunk {
                        batch.put_cf(cf_default_ref, row.id.as_bytes(), &vec![]);

                        // Ports
                        batch.put_cf(
                            cf_ports,
                            row.id.as_bytes(),
                            row.ports_to_string().as_bytes(),
                        );

                        // Services
                        batch.put_cf(
                            cf_services,
                            row.id.as_bytes(),
                            row.services.join(",").into_bytes(),
                        );

                        // Responses
                        batch.put_cf(cf_responses, row.id.as_bytes(), row.responses.into_bytes());
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
                QueryDataType::Host(row) => {
                    return Ok(vec![
                        self.get_row_by_host(row.to_string().as_str())
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
                id: row_id.to_string(),
                ports: split_nums(&self.row_to_string(db, row_id, &cfs[1]), ","),
                services: self
                    .row_to_string(db, row_id, &cfs[2])
                    .split(",")
                    .map(|a| a.to_string())
                    .collect(),
                responses: self.row_to_string(db, row_id, &cfs[3]),
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
    Host(IpAddr),
    Port(QueryType, i32),
    Service(QueryType, String, String),
    FullTextIncludes(String),
}

#[derive(Debug)]
pub enum QueryType {
    Equals,
    NotEquals,
    Includes,
    NotIncludes,
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

/// Collect all keys from the ports column family as potential candidates
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

/// Filter keys by port queries
fn filter_by_port_queries(
    db: &DB,
    cf_ports: &ColumnFamily,
    keys: Vec<Vec<u8>>,
    port_queries: &[QueryDataType],
) -> Vec<Vec<u8>> {
    keys.into_iter()
        .filter(|key| {
            // Get the ports string for this key
            if let Ok(Some(ports_value)) = db.get_cf(cf_ports, key) {
                if let Ok(ports_str) = std::str::from_utf8(&ports_value) {
                    let ports: Vec<i32> = ports_str
                        .split(',')
                        .filter_map(|p| p.trim().parse::<i32>().ok())
                        .collect();

                    // Check if all port queries are satisfied
                    port_queries.iter().all(|query| {
                        if let QueryDataType::Port(query_type, port_num) = query {
                            match query_type {
                                QueryType::Equals => ports.contains(port_num),
                                QueryType::NotEquals => !ports.contains(port_num),
                                QueryType::Includes => ports.contains(port_num),
                                QueryType::NotIncludes => !ports.contains(port_num),
                            }
                        } else {
                            false // Not a port query
                        }
                    })
                } else {
                    false
                }
            } else {
                false
            }
        })
        .collect()
}

/// Filter keys by service queries
fn filter_by_service_queries(
    db: &DB,
    cf_services: &ColumnFamily,
    keys: Vec<Vec<u8>>,
    service_queries: &[QueryDataType],
) -> Vec<Vec<u8>> {
    keys.into_iter()
        .filter(|key| {
            // Get the services string for this key
            if let Ok(Some(services_value)) = db.get_cf(cf_services, key) {
                if let Ok(services_str) = std::str::from_utf8(&services_value) {
                    let services: Vec<&str> = services_str.split(',').map(|s| s.trim()).collect();

                    // Get the responses hashmap for this key
                    if let Ok(Some(responses_value)) =
                        db.get_cf(db.cf_handle("responses").unwrap(), key)
                    {
                        if let Ok(responses_str) = std::str::from_utf8(&responses_value) {
                            if let Ok(responses_map) = serde_json::from_str::<
                                HashMap<String, (String, String)>,
                            >(responses_str)
                            {
                                // Check if all service queries are satisfied
                                service_queries.iter().all(|query| {
                                    if let QueryDataType::Service(
                                        query_type,
                                        service_name,
                                        data_str,
                                    ) = query
                                    {
                                        // Check across all responses in the hashmap
                                        responses_map.values().any(|(service, data)| {
                                            match query_type {
                                                QueryType::Equals => {
                                                    service == service_name && data == data_str
                                                }
                                                QueryType::NotEquals => {
                                                    service != service_name || data != data_str
                                                }
                                                QueryType::Includes => {
                                                    service.contains(service_name)
                                                        && data.contains(data_str)
                                                }
                                                QueryType::NotIncludes => {
                                                    !service.contains(service_name)
                                                        || !data.contains(data_str)
                                                }
                                            }
                                        })
                                    } else {
                                        false // Not a service query
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
                } else {
                    false
                }
            } else {
                false
            }
        })
        .collect()
}

/// Filter keys by fulltext queries (most expensive operation)
fn filter_by_fulltext_queries(
    db: &DB,
    cf_responses: &ColumnFamily,
    keys: Vec<Vec<u8>>,
    fulltext_queries: &[QueryDataType],
) -> Vec<Vec<u8>> {
    keys.into_iter()
        .filter(|key| {
            // Get the raw responses string for this key
            if let Ok(Some(responses_value)) = db.get_cf(cf_responses, key) {
                if let Ok(responses_str) = std::str::from_utf8(&responses_value) {
                    // Check if all fulltext queries are satisfied
                    fulltext_queries.iter().all(|query| {
                        if let QueryDataType::FullTextIncludes(search_str) = query {
                            responses_str.contains(search_str)
                        } else {
                            false // Not a fulltext query
                        }
                    })
                } else {
                    false
                }
            } else {
                false
            }
        })
        .collect()
}

/// Optimized search implementation with parallelism for large datasets
pub fn search_parallel(
    db: &DB,
    queries: Vec<QueryDataType>,
    cfs: &Vec<&ColumnFamily>,
) -> Vec<Vec<u8>> {
    // Get column family handles
    let cf_ports = cfs[1];
    let cf_services = cfs[2];
    let cf_responses = cfs[3];

    // Collect all keys as potential candidates
    let potential_keys = collect_all_keys(db, cf_ports);

    // Partition queries by type
    let port_queries: Vec<_> = queries
        .iter()
        .filter_map(|q| {
            if let QueryDataType::Port(_, _) = q {
                Some(q)
            } else {
                None
            }
        })
        .collect();

    let service_queries: Vec<_> = queries
        .iter()
        .filter_map(|q| {
            if let QueryDataType::Service(_, _, _) = q {
                Some(q)
            } else {
                None
            }
        })
        .collect();

    let fulltext_queries: Vec<_> = queries
        .iter()
        .filter_map(|q| {
            if let QueryDataType::FullTextIncludes(_) = q {
                Some(q)
            } else {
                None
            }
        })
        .collect();

    // Load all data for batch processing to minimize DB reads
    let mut ports_data = HashMap::new();
    let mut services_data = HashMap::new();
    let mut responses_data = HashMap::new();

    for key in &potential_keys {
        if let Ok(Some(value)) = db.get_cf(cf_ports, key) {
            ports_data.insert(key.clone(), value);
        }

        if let Ok(Some(value)) = db.get_cf(cf_services, key) {
            services_data.insert(key.clone(), value);
        }

        if let Ok(Some(value)) = db.get_cf(cf_responses, key) {
            responses_data.insert(key.clone(), value);
        }
    }

    // Process in parallel using rayon
    let matching_keys: Vec<Vec<u8>> = potential_keys
        .into_par_iter()
        .filter(|key| {
            // Check port queries
            let ports_match = port_queries.is_empty()
                || if let Some(ports_value) = ports_data.get(key) {
                    if let Ok(ports_str) = std::str::from_utf8(ports_value) {
                        let ports: Vec<i32> = ports_str
                            .split(',')
                            .filter_map(|p| p.trim().parse::<i32>().ok())
                            .collect();

                        port_queries.iter().all(|query| {
                            if let QueryDataType::Port(query_type, port_num) = *query {
                                match query_type {
                                    QueryType::Equals => ports_str == port_num.to_string(),
                                    QueryType::NotEquals => ports_str != port_num.to_string(),
                                    QueryType::Includes => ports.contains(port_num),
                                    QueryType::NotIncludes => !ports.contains(port_num),
                                }
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                } else {
                    false
                };

            if !ports_match {
                return false;
            }

            // Check service queries
            let services_match = service_queries.is_empty()
                || if let (Some(services_value), Some(responses_value)) =
                    (services_data.get(key), responses_data.get(key))
                {
                    if let (Ok(services_str), Ok(responses_str)) = (
                        std::str::from_utf8(services_value),
                        std::str::from_utf8(responses_value),
                    ) {
                        if let Ok(responses_map) =
                            serde_json::from_str::<HashMap<String, (String, String)>>(responses_str)
                        {
                            service_queries.iter().all(|query| {
                                if let QueryDataType::Service(query_type, service_name, data_str) =
                                    *query
                                {
                                    responses_map
                                        .values()
                                        .any(|(service, data)| match query_type {
                                            QueryType::Equals => {
                                                service == service_name && data == data_str
                                            }
                                            QueryType::NotEquals => {
                                                service != service_name || data != data_str
                                            }
                                            QueryType::Includes => {
                                                service == service_name && data.contains(data_str)
                                            }
                                            QueryType::NotIncludes => {
                                                service != service_name || !data.contains(data_str)
                                            }
                                        })
                                } else {
                                    false
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
                };

            if !services_match {
                return false;
            }

            // Check fulltext queries
            let fulltext_match = fulltext_queries.is_empty()
                || if let Some(responses_value) = responses_data.get(key) {
                    if let Ok(responses_str) = std::str::from_utf8(responses_value) {
                        fulltext_queries.iter().all(|query| {
                            if let QueryDataType::FullTextIncludes(search_str) = *query {
                                responses_str.contains(search_str)
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                } else {
                    false
                };

            fulltext_match
        })
        .collect();

    matching_keys
}
