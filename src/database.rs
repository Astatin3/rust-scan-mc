use std::{
    collections::HashSet,
    io::Error,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use memchr::memmem;
use rocksdb::{Cache, ColumnFamily, DB, IteratorMode, Options, ReadOptions, WriteBatch};
use serde::{Deserialize, Serialize};

use crate::port_scan::port_scan::ScanResult;

static COLUMN_COUNT: usize = 5;
static TEST_ROW_COUNT: usize = 1000;

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
    pub id: String,          // Row identifier
    pub values: Vec<String>, // Array of string values
}

impl StringRow {
    pub fn to_string(&self) -> String {
        let mut str = "".to_string();

        str += format!("Row ID: {}, Values: [", self.id).as_str();
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                str += ", ";
            }
            str += format!("{}: \"{}\"", i, value).as_str();
        }
        str += "]";

        str
    }
}

/// Enum for defining search criteria
#[derive(Debug)]
enum SearchCriteria {
    ByColumnValue(usize, String), // Search by specific column value
    ByColumnPrefix(usize, String), // Search by column value prefix
                                  // ByIdRange(String, String),     // Search by ID range
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

        let mut column_families = vec!["default".to_string()]; // Main data store

        // Add column families for each column index we might want to search by
        // (for demo, we'll create indexes for 5 potential columns)
        for i in 0..COLUMN_COUNT {
            column_families.push(format!("col{}_idx", i).to_string());
        }

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
                values: vec![],
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
        let cf_default = db.cf_handle("default").unwrap();

        // Get handles to column index families
        let mut cf_columns = Vec::new();
        for i in 0..3 {
            let cf = db.cf_handle(&format!("col{}_idx", i)).unwrap();
            cf_columns.push(cf);
        }

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
            let cf_columns_ref = &cf_columns;

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

                        // Create indexes only for searchable columns (0-2)
                        for (col_idx, value) in row.values.iter().enumerate() {
                            if col_idx < cf_columns_ref.len() {
                                // Create search-friendly keys: value:rowid
                                // Use minimal escaping for better performance
                                let idx_key = format!("{}:{}", fast_escape(value), row.id);
                                batch.put_cf(
                                    cf_columns_ref[col_idx],
                                    idx_key.as_bytes(),
                                    row.id.as_bytes(),
                                );
                            }
                        }
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
                        if let Some(row) = decode_row_binary(&value_bytes) {
                            matching_keys.push(row);
                        }
                    }
                }
            }
        }

        Ok(matching_keys)
    }
}

// Count results from a search without printing
fn search(
    db: &DB,
    cf_default: &ColumnFamily,
    cf_columns: &[&ColumnFamily],
    criteria: SearchCriteria,
) -> Result<Vec<StringRow>, Box<dyn std::error::Error>> {
    let mut results: Vec<StringRow> = Vec::new();

    match criteria {
        SearchCriteria::ByColumnValue(col_idx, value) => {
            if col_idx >= cf_columns.len() {
                return Ok(results);
            }

            // Create search key with escaped value
            let prefix = format!("{}:", fast_escape(&value));
            let mut opts = ReadOptions::default();
            opts.set_prefix_same_as_start(true);

            let iterator = db.iterator_cf_opt(
                cf_columns[col_idx],
                opts,
                rocksdb::IteratorMode::From(prefix.as_bytes(), rocksdb::Direction::Forward),
            );

            for item in iterator {
                let (idx_key, data) = item?;
                let idx_key_str = String::from_utf8(idx_key.to_vec())?;

                // Skip if we've moved past our prefix
                if !idx_key_str.starts_with(&prefix) {
                    break;
                }

                let row = decode_row_binary(&data);

                if let Some(row) = row {
                    results.push(row);
                }
            }
        }

        SearchCriteria::ByColumnPrefix(col_idx, prefix) => {
            if col_idx >= cf_columns.len() {
                return Ok(results);
            }

            // Create search key with escaped prefix
            let search_prefix = fast_escape(&prefix);

            let iterator = db.iterator_cf(
                cf_columns[col_idx],
                rocksdb::IteratorMode::From(search_prefix.as_bytes(), rocksdb::Direction::Forward),
            );

            for item in iterator {
                let (idx_key, data) = item?;
                let idx_key_str = String::from_utf8(idx_key.to_vec())?;

                // Extract just the value part of the index key
                let parts: Vec<&str> = idx_key_str.splitn(2, ':').collect();
                if parts.len() < 2 {
                    continue;
                }

                let value_part = fast_unescape(parts[0]);

                // Skip if value doesn't start with our prefix
                if !value_part.starts_with(&prefix) {
                    // If we've moved past potential matches, break early
                    if value_part > prefix {
                        break;
                    }
                    continue;
                }

                let row = decode_row_binary(&data);

                if let Some(row) = row {
                    results.push(row);
                }
            }
        }
    }

    Ok(results)
}

// Fast minimal escaping for key values
#[inline]
fn fast_escape(s: &str) -> String {
    // Only escape the colon character which is our separator
    s.replace(":", "\\:")
}

// Fast unescaping for key values
#[inline]
fn fast_unescape(s: &str) -> String {
    // Only unescape the colon
    s.replace("\\:", ":")
}

// Fast direct row fetch by ID
fn fetch_row(db: &DB, cf_default: &ColumnFamily, row_id: &str) -> Option<StringRow> {
    match db.get_cf(cf_default, row_id.as_bytes()) {
        Ok(Some(value)) => decode_row_binary(&value),
        _ => None,
    }
}

// Fast column value fetch
fn fetch_column(db: &DB, cf_default: &ColumnFamily, row_id: &str, column_idx: usize) -> String {
    match fetch_row(db, cf_default, row_id) {
        Some(row) => get_column_value(&row, column_idx),
        None => String::new(),
    }
}

// Get a column value, returning empty string if column doesn't exist
#[inline]
fn get_column_value(row: &StringRow, column_index: usize) -> String {
    if column_index < row.values.len() {
        row.values[column_index].clone()
    } else {
        String::new() // Return empty string for missing columns
    }
}

// Binary decoding of row data
fn decode_row_binary(data: &[u8]) -> Option<StringRow> {
    if data.len() < 8 {
        return None;
    }

    let mut pos = 0;

    // Read ID length
    let mut id_len_bytes = [0u8; 4];
    id_len_bytes.copy_from_slice(&data[pos..pos + 4]);
    let id_len = u32::from_le_bytes(id_len_bytes) as usize;
    pos += 4;

    // Read ID
    if pos + id_len > data.len() {
        return None;
    }
    let id = String::from_utf8_lossy(&data[pos..pos + id_len]).to_string();
    pos += id_len;

    // Read number of values
    if pos + 4 > data.len() {
        return None;
    }
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

    Some(StringRow { id, values })
}

// Binary encoding of row data for maximum performance
fn encode_row_binary(buf: &mut Vec<u8>, row: &StringRow) {
    // Write ID length and ID
    let id_bytes = row.id.as_bytes();
    buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(id_bytes);

    // Write number of values
    buf.extend_from_slice(&(row.values.len() as u32).to_le_bytes());

    // Write each value
    for value in &row.values {
        let value_bytes = value.as_bytes();
        buf.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(value_bytes);
    }
}

// fn benchmark_create_rows() {
//     for i in 0..10000 {
//         // Generate 10,000 test rows
//         let mut values = Vec::with_capacity(5);

//         // Add IP address (column 0)
//         if i % 3 == 0 {
//             values.push(format!("192.168.1.{}", i % 255));
//         } else if i % 3 == 1 {
//             values.push(format!("10.0.{}.{}", (i / 255) % 255, i % 255));
//         } else {
//             values.push(format!("172.16.{}.{}", (i / 255) % 255, i % 255));
//         }

//         // Add status (column 1)
//         if i % 5 < 4 {
//             // 80% active
//             values.push("active".to_string());
//         } else {
//             values.push("inactive".to_string());
//         }

//         // Add response time (column 2) for active servers
//         if i % 5 < 4 {
//             values.push(format!("{}ms", (i % 100) + 1));
//         }

//         // Add server name (column 3)
//         if i % 2 == 0 {
//             values.push(format!("server{:04}", i));
//         }

//         // Add priority (column 4) for some servers
//         if i % 7 == 0 {
//             values.push("high_priority".to_string());
//         } else if i % 11 == 0 {
//             values.push("low_priority".to_string());
//         }

//         // string_rows.push(StringRow {
//         //     id: format!("row{:06}", i),
//         //     values,
//         // });
//     }
// }

// // Benchmark search performance
// fn benchmark_search<F>(
//     db: &DB,
//     cf_default: &ColumnFamily,
//     cf_columns: &[&ColumnFamily],
//     name: &str,
//     criteria_fn: F,
// ) -> Result<(), Box<dyn std::error::Error>>
// where
//     F: Fn() -> SearchCriteria,
// {
//     let mut total_duration = Duration::from_secs(0);
//     let mut total_results = 0;

//     for i in 1..=3 {
//         let criteria = criteria_fn();
//         let start = Instant::now();
//         let count = count_search_results(db, cf_default, cf_columns, criteria)?;
//         let duration = start.elapsed();

//         total_duration += duration;
//         total_results = count; // All runs should return same count

//         println!("  Run {}: Found {} results in {:?}", i, count, duration);
//     }

//     let avg_duration = total_duration / 3;
//     println!(
//         "  Average: {:?} for {} results",
//         avg_duration, total_results
//     );
//     println!(
//         "  Speed: {:.2} results/ms",
//         total_results as f64 / avg_duration.as_millis() as f64
//     );

//     Ok(())
// }

// // Benchmark direct row fetch performance
// fn benchmark_direct_fetch(
//     db: &DB,
//     cf_default: &ColumnFamily,
//     name: &str,
//     row_id: &str,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let mut total_duration = Duration::from_secs(0);

//     for i in 1..=3 {
//         let start = Instant::now();

//         // Do multiple fetches to get a measurable time
//         for _ in 0..1000 {
//             let _ = fetch_row(db, cf_default, row_id);
//         }

//         let duration = start.elapsed();
//         total_duration += duration;

//         println!("  Run {}: 1000 row fetches in {:?}", i, duration);
//     }

//     let avg_duration = total_duration / 3;
//     println!("  Average: {:?} for 1000 fetches", avg_duration);
//     println!(
//         "  Speed: {:.2} fetches/ms",
//         1000.0 / avg_duration.as_millis() as f64
//     );

//     Ok(())
// }

// // Benchmark column fetch performance
// fn benchmark_column_fetch(
//     db: &DB,
//     cf_default: &ColumnFamily,
//     name: &str,
//     row_id: &str,
//     col_idx: usize,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let mut total_duration = Duration::from_secs(0);

//     for i in 1..=3 {
//         let start = Instant::now();

//         // Do multiple fetches to get a measurable time
//         for _ in 0..1000 {
//             let _ = fetch_column(db, cf_default, row_id, col_idx);
//         }

//         let duration = start.elapsed();
//         total_duration += duration;

//         println!("  Run {}: 1000 column fetches in {:?}", i, duration);
//     }

//     let avg_duration = total_duration / 3;
//     println!("  Average: {:?} for 1000 fetches", avg_duration);
//     println!(
//         "  Speed: {:.2} fetches/ms",
//         1000.0 / avg_duration.as_millis() as f64
//     );

//     Ok(())
// }
//
// // Example usage with batching for very large datasets
