use std::{net::IpAddr, sync::Arc, time::Instant};

use rocksdb::{Cache, ColumnFamily, IteratorMode, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};

use crate::port_scan::port_scan::ScanResult;

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
pub struct StringRow {
    pub id: String,      // Row identifier
    pub ports: Vec<i32>, // Array of string values
}

impl StringRow {
    pub fn to_string(&self) -> String {
        let mut str = "".to_string();

        str += format!("{} - ports: [{}]", self.id, join_nums(&self.ports, ",")).as_str();

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

        let column_families = vec!["default".to_string(), "ports".to_string()];

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
            string_rows.push(StringRow {
                id: result.to_string(),
                ports: vec![],
            });
        }

        return self.save_rows(string_rows);
    }

    pub fn add_tcp_results(
        &self,
        results: &Vec<ScanResult>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut string_rows = Vec::with_capacity(results.len()); // Pre-allocate capacity

        for result in results {
            string_rows.push(result.to_string_row());
        }

        return self.save_rows(string_rows);
    }

    pub fn save_rows(&self, string_rows: Vec<StringRow>) -> Result<(), Box<dyn std::error::Error>> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);
        let cf_default = db.cf_handle(&self.columns[0]).unwrap();
        let cf_ports = db.cf_handle(&self.columns[1]).unwrap();

        let start = Instant::now();
        let length = string_rows.len();

        // Split the rows into chunks for parallel processing
        let chunks: Vec<Vec<StringRow>> = string_rows
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
                        // Use optimized binary format for the main data
                        let mut data = Vec::with_capacity(256);

                        // Format: id_len + id + count + (len + str) for each value
                        // Binary format: direct encoding without JSON overhead
                        encode_row_binary(&mut data, &row);

                        // Store in main column family
                        batch.put_cf(cf_default_ref, row.id.as_bytes(), &data);

                        let idx_key =
                            format!("{}:{}", fast_escape(row.ports_to_string().as_str()), row.id);
                        batch.put_cf(cf_ports, idx_key.as_bytes(), row.id.as_bytes());
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

    pub fn get_row_by_host(&self, row: &str) -> Option<StringRow> {
        let db = DB::open_cf(&self.options, &self.path, &self.columns);
        if db.is_err() {
            return None;
        };
        let db = db.unwrap();
        let cf_default = db.cf_handle("default").unwrap();

        return fetch_row(&db, cf_default, row);
    }

    pub fn get_rows_by_port(&self, port: &str) -> Vec<StringRow> {
        if let Ok(result) = self.search_substring_in_column(self.columns[0].as_str(), port) {
            return result;
        } else {
            return Vec::new();
        }
    }

    pub fn search_substring_in_column(
        &self,
        column: &str,
        substring: &str,
    ) -> Result<Vec<StringRow>, rocksdb::Error> {
        let db = Arc::new(DB::open_cf(&self.options, &self.path, &self.columns)?);

        let cf = db.cf_handle(column).unwrap();

        let mut matching_keys: Vec<StringRow> = Vec::new();

        // Use RocksDB's iterator for efficient scanning
        let iter = db.iterator_cf(cf, IteratorMode::Start);

        // Iterate through all key-value pairs in the column family
        for item in iter {
            let (key_bytes, value_bytes) = item?;

            // Convert value to string (assumes UTF-8 encoding)
            if let Ok(value_str) = std::str::from_utf8(&value_bytes) {
                // Check if the value contains the substring
                if value_str.contains(substring) {
                    // Convert key to string and add to results
                    if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                        if let Some(row) = decode_row_binary(key_str, &value_bytes) {
                            matching_keys.push(row);
                        }
                    }
                }
            }
        }

        Ok(matching_keys)
    }
}

// Fast minimal escaping for key values
#[inline]
fn fast_escape(s: &str) -> String {
    // Only escape the colon character which is our separator
    s.replace(":", "\\:")
}

// Fast unescaping for key values
#[inline]

// Fast direct row fetch by ID
fn fetch_row(db: &DB, cf_default: &ColumnFamily, row_id: &str) -> Option<StringRow> {
    match db.get_cf(cf_default, row_id.as_bytes()) {
        Ok(Some(value)) => decode_row_binary(row_id, &value),
        _ => None,
    }
}
// Binary decoding of row data
fn decode_row_binary(key: &str, data: &[u8]) -> Option<StringRow> {
    if data.len() < 8 {
        return None;
    }

    let mut pos = 0;

    let mut values_count_bytes = [0u8; 4];
    values_count_bytes.copy_from_slice(&data[pos..pos + 4]);
    let values_count = u32::from_le_bytes(values_count_bytes) as usize;
    pos += 4;

    // Read values
    let mut values = Vec::with_capacity(values_count);
    for _ in 0..values_count {
        if pos + 4 > data.len() {
            return None;
        }

        let mut value_len_bytes = [0u8; 4];
        value_len_bytes.copy_from_slice(&data[pos..pos + 4]);
        let value_len = u32::from_le_bytes(value_len_bytes) as usize;
        pos += 4;

        if pos + value_len > data.len() {
            return None;
        }

        let value = String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
        values.push(value);
        pos += value_len;
    }

    Some(StringRow {
        id: key.to_string(),
        ports: split_nums(values[0].as_str(), ","),
    })
}

// Binary encoding of row data for maximum performance
fn encode_row_binary(buf: &mut Vec<u8>, row: &StringRow) {
    let values = vec![row.ports_to_string()];

    // Write number of values
    buf.extend_from_slice(&(values.len() as u32).to_le_bytes());

    // Write each value
    for value in vec![row.ports_to_string()] {
        let value_bytes = value.as_bytes();
        buf.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(value_bytes);
    }
}
