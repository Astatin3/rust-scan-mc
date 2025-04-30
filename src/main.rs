use std::{
    cmp::min,
    env,
    ffi::OsString,
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use parse_ip_range::parse_ip_targets;
use rand::{rng, seq::SliceRandom};
use untitled::{
    database::ResultDatabase, online_scan, parse_ip_range, port_scan::tcp_scan, query,
    service_scan::service_scan::scan_services,
};

const BATCH_SIZE: usize = 4096;

/// A fictional versioning CLI
#[derive(Debug, Parser)]
#[command(name = "rust-scan-mc")]
#[command(about = "Tool for scanning Minecraft servers", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scans servers
    #[command(arg_required_else_help = true)]
    Scan {
        /// List of remote servers
        hosts: String,
        /// Timeout for requests
        #[arg(short, long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Delay between icmp echo requests
        #[arg(short, long, default_value_t = 80)]
        ping_delay_micros: u64,
        /// Delay between tcp syn packets
        #[arg(short, long, default_value_t = 100)]
        syn_tcp_delay_micros: u64,
    },
    /// Retrieves queries
    #[command(arg_required_else_help = true)]
    Search {
        /// The search query
        query: Vec<String>,
    },
    /// Rescans servers from search query
    Rescan {
        /// The search query
        query: Vec<String>,
        /// Timeout for requests
        #[arg(short, long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Delay between icmp echo requests
        #[arg(short, long, default_value_t = 80)]
        ping_delay_micros: u64,
        /// Delay between tcp syn packets
        #[arg(short, long, default_value_t = 100)]
        syn_tcp_delay_micros: u64,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let database = ResultDatabase::new("ping_result_database");

    match args.command {
        Commands::Scan {
            hosts,
            timeout_ms,
            ping_delay_micros,
            syn_tcp_delay_micros,
        } => {
            let hosts = parse_ip_targets(&hosts)?;

            scan(
                database,
                hosts,
                Duration::from_millis(timeout_ms),
                Duration::from_micros(ping_delay_micros),
                Duration::from_micros(syn_tcp_delay_micros),
            )?;
        }
        Commands::Rescan {
            query,
            timeout_ms,
            ping_delay_micros,
            syn_tcp_delay_micros,
        } => {
            rescan(
                database,
                query,
                Duration::from_millis(timeout_ms),
                Duration::from_micros(ping_delay_micros),
                Duration::from_micros(syn_tcp_delay_micros),
            )?;
        }
        Commands::Search { query } => {
            let start = Instant::now();
            if let Ok(query) = query::search(query) {
                let results = database.search(query);
                if let Ok(results) = results {
                    let len = results.len();
                    for result in results {
                        println!("{}", result.to_string());
                    }
                    println!("{} results in {}ms", len, start.elapsed().as_millis());
                }
            }
        }
        _ => {}
    }

    Ok(())
}

const PORTS_1: [i32; 713] = [
    1337, 2000, 2001, 2006, 2012, 2018, 2024, 6969, 7777, 10000, 10001, 10002, 10003, 10004, 10005,
    10006, 10007, 10008, 10009, 10010, 10020, 10030, 10040, 10050, 10060, 10070, 10080, 10090,
    10100, 10110, 10120, 10140, 10150, 10160, 10200, 10230, 10250, 10400, 10600, 10800, 11000,
    11200, 11400, 11600, 11800, 12000, 12200, 12345, 12400, 12600, 12800, 13000, 13200, 13400,
    13600, 13800, 14000, 14200, 14400, 14600, 14800, 15000, 15200, 15400, 15600, 15800, 16000,
    16200, 16400, 16600, 16800, 17000, 17200, 17400, 17600, 17800, 18000, 18200, 18400, 18600,
    18800, 19000, 19132, 19200, 19400, 19600, 19800, 20000, 20001, 20002, 20200, 20400, 20600,
    20800, 21000, 21200, 21400, 21600, 21800, 22000, 22200, 22222, 22400, 22600, 22800, 23000,
    23200, 23400, 23600, 24000, 24200, 24400, 24600, 24800, 25000, 25001, 25003, 25004, 25073,
    25110, 25126, 25200, 25216, 25400, 25417, 25500, 25501, 25502, 25503, 25504, 25505, 25506,
    25507, 25510, 25511, 25512, 25515, 25520, 25522, 25525, 25535, 25541, 25542, 25545, 25550,
    25551, 25552, 25553, 25554, 25555, 25556, 25558, 25559, 25560, 25561, 25562, 25563, 25564,
    25565, 25566, 25567, 25568, 25569, 25570, 25571, 25572, 25573, 25574, 25575, 25576, 25577,
    25578, 25579, 25580, 25581, 25582, 25583, 25584, 25585, 25586, 25587, 25588, 25589, 25590,
    25591, 25592, 25593, 25594, 25595, 25596, 25597, 25598, 25599, 25600, 25601, 25602, 25603,
    25604, 25605, 25606, 25607, 25608, 25609, 25610, 25611, 25612, 25613, 25614, 25615, 25616,
    25617, 25618, 25619, 25620, 25621, 25622, 25623, 25624, 25625, 25626, 25627, 25628, 25629,
    25630, 25631, 25632, 25633, 25634, 25635, 25636, 25637, 25638, 25639, 25640, 25641, 25642,
    25643, 25644, 25645, 25646, 25647, 25648, 25649, 25650, 25651, 25652, 25653, 25654, 25655,
    25656, 25657, 25658, 25659, 25660, 25661, 25662, 25663, 25664, 25665, 25666, 25667, 25668,
    25669, 25670, 25671, 25672, 25673, 25674, 25675, 25676, 25677, 25678, 25679, 25680, 25681,
    25682, 25683, 25684, 25685, 25686, 25687, 25688, 25689, 25690, 25692, 25693, 25695, 25696,
    25697, 25700, 25702, 25705, 25708, 25714, 25720, 25725, 25726, 25732, 25738, 25744, 25745,
    25750, 25756, 25762, 25765, 25768, 25774, 25780, 25785, 25786, 25792, 25798, 25800, 25804,
    25805, 25810, 25816, 25822, 25825, 25828, 25834, 25840, 25845, 25846, 25852, 25858, 25864,
    25865, 25870, 25876, 25882, 25885, 25888, 25894, 25900, 25905, 25906, 25918, 25924, 25925,
    25930, 25936, 25942, 25945, 25948, 25954, 25965, 25966, 25972, 25978, 25984, 25985, 25990,
    25996, 26000, 26002, 26005, 26008, 26014, 26020, 26025, 26026, 26032, 26038, 26044, 26045,
    26056, 26062, 26065, 26068, 26080, 26085, 26092, 26098, 26104, 26105, 26116, 26122, 26125,
    26134, 26140, 26145, 26146, 26158, 26164, 26165, 26170, 26176, 26185, 26188, 26194, 26200,
    26205, 26212, 26225, 26230, 26236, 26242, 26245, 26248, 26254, 26265, 26266, 26278, 26284,
    26285, 26296, 26302, 26305, 26320, 26325, 26326, 26332, 26338, 26344, 26345, 26350, 26362,
    26365, 26380, 26385, 26386, 26392, 26398, 26400, 26404, 26405, 26425, 26445, 26465, 26476,
    26485, 26505, 26525, 26545, 26565, 26566, 26585, 26600, 26605, 26625, 26645, 26665, 26685,
    26705, 26725, 26745, 26765, 26785, 26800, 26805, 26825, 26845, 26865, 26885, 26905, 26925,
    26945, 26965, 26985, 27000, 27005, 27015, 27025, 27065, 27085, 27165, 27200, 27265, 27365,
    27400, 27465, 27565, 27600, 27665, 27765, 27800, 27865, 27965, 28000, 28065, 28165, 28265,
    28365, 28400, 28465, 28565, 28665, 28765, 28800, 28865, 28965, 29000, 29065, 29165, 29200,
    29265, 29365, 29400, 29465, 29565, 29600, 29665, 29765, 29800, 29865, 29965, 30000, 30001,
    30002, 30015, 30065, 30165, 30200, 30265, 30365, 30400, 30465, 30565, 30600, 30665, 30765,
    30800, 30865, 30965, 31000, 31065, 31165, 31200, 31265, 31365, 31400, 31465, 31565, 31665,
    31765, 31800, 31865, 31965, 32000, 32065, 32165, 32265, 32365, 32400, 32465, 32565, 32600,
    32665, 32765, 32800, 32865, 32965, 33000, 33065, 33165, 33200, 33265, 33365, 33400, 33465,
    33565, 33600, 33665, 33765, 33800, 33865, 33965, 34000, 34065, 34165, 34200, 34265, 34365,
    34400, 34465, 34565, 34600, 34665, 34800, 35000, 35400, 35565, 35600, 35800, 36000, 36400,
    36600, 37000, 37600, 37800, 38000, 38200, 38600, 38800, 39000, 39400, 40000, 40001, 40400,
    40600, 41000, 41200, 41400, 41600, 42000, 42069, 42200, 42400, 42600, 42800, 43000, 43600,
    43800, 44000, 44200, 44400, 44600, 44800, 44955, 44956, 44957, 44958, 44959, 44961, 45000,
    45200, 45400, 45600, 45800, 46000, 46200, 46400, 46600, 46800, 47000, 47200, 47400, 47600,
    47800, 48000, 48200, 48400, 48800, 49400, 49600, 49800, 50000, 50001, 50002, 50200, 50400,
    50600, 51000, 51200, 51400, 51600, 51800, 52000, 52200, 52400, 52600, 52800, 53200, 53800,
    54000, 54200, 54600, 54800, 55000, 55400, 55555, 55600, 55800, 56000, 56200, 56400, 56600,
    57200, 57400, 57600, 57800, 58200, 58600, 58800, 59000, 59200, 59400, 59800, 60200, 60400,
    60600, 60800, 61000, 61200, 61400, 61600, 62000, 62200, 62400, 62800, 63000, 63200, 63400,
    63600, 63800, 64000, 64200, 64400, 64600, 64800, 65000, 65200,
];

const PORTS_2: [i32; 171] = [
    10000, 10010, 10020, 19132, 25500, 25501, 25555, 25560, 25561, 25562, 25563, 25564, 25565,
    25566, 25567, 25568, 25569, 25570, 25571, 25572, 25573, 25574, 25575, 25576, 25577, 25578,
    25579, 25580, 25581, 25582, 25583, 25584, 25585, 25586, 25587, 25588, 25589, 25590, 25591,
    25592, 25593, 25594, 25595, 25596, 25597, 25598, 25599, 25600, 25601, 25602, 25603, 25604,
    25605, 25606, 25607, 25608, 25609, 25610, 25611, 25612, 25613, 25614, 25615, 25616, 25617,
    25618, 25619, 25620, 25621, 25622, 25623, 25624, 25625, 25626, 25627, 25628, 25629, 25630,
    25631, 25632, 25633, 25635, 25636, 25642, 25645, 25648, 25665, 25666, 25685, 25700, 25765,
    25865, 25965, 26065, 26165, 26265, 26365, 26465, 26565, 26665, 26765, 26865, 26965, 27065,
    27165, 27265, 27365, 27465, 27565, 27665, 27765, 27865, 27965, 28065, 28165, 28265, 28365,
    28465, 28565, 28665, 28765, 28865, 28965, 29065, 29165, 29265, 29365, 29465, 29565, 29665,
    29765, 29865, 29965, 30000, 30065, 30165, 30265, 30365, 30465, 30565, 30665, 30765, 30865,
    30965, 31065, 31165, 31265, 31365, 31465, 31565, 31665, 31765, 31865, 31965, 32065, 32165,
    32265, 32365, 32465, 32565, 32665, 32765, 32865, 32965, 33065, 33165, 33265, 33365, 33565,
    33665, 44955,
];

fn scan(
    database: ResultDatabase,
    hosts: Vec<IpAddr>,
    timeout: Duration,
    ping_delay: Duration,
    tcp_delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse the targets into IP addresses
    // let hosts = parse_ip_targets(&hosts)?;

    // println!("{:?}", hosts);

    let chunks = hosts.chunks(BATCH_SIZE);
    let num_chunks = chunks.len();
    for (i, hosts) in chunks.enumerate() {
        let hosts = hosts.to_vec();
        let length = hosts.len();

        println!("Scanning chunk {}/{} ({} hosts)", i + 1, num_chunks, length);

        let up_hosts: Vec<IpAddr> =
            online_scan::ping_scanner::ping_scan(hosts, timeout, ping_delay).unwrap();
        let up_len = up_hosts.len();
        println!(
            "Finished Pinging! {} Scanned, {} Up",
            length,
            up_hosts.len()
        );

        let tcp_results = tcp_scan::tcp_scan(up_hosts, PORTS_2.to_vec(), timeout, tcp_delay);
        println!("Finished port scan");

        let service_results = scan_services(tcp_results, min(50, up_len), timeout);
        println!("Finished service scan");
        let _ = database.add_data_row(service_results);
    }

    Ok(())
}

fn rescan(
    database: ResultDatabase,
    query: Vec<String>,
    timeout: Duration,
    ping_delay: Duration,
    tcp_delay: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    if let Ok(query) = query::search(query) {
        let results = database.search(query);
        if let Ok(results) = results {
            let len = results.len();

            let mut hosts: Vec<IpAddr> = Vec::new();

            for result in results {
                println!("{}", result.to_string());
                hosts.push(IpAddr::from_str(result.ip.as_str()).unwrap());
            }
            println!("{} results in {}ms", len, start.elapsed().as_millis());

            hosts.sort();
            hosts.dedup();
            hosts.shuffle(&mut rng());

            scan(database, hosts, timeout, ping_delay, tcp_delay)?;
        }
    }

    Ok(())
}

fn print_help(arg: Option<&str>) {
    println!(
        "{}",
        match arg {
            None => {
                "rust-scan help menu
Commands:
    scan   <type> <hosts> - scan a block of addresses and check for online using icmp echo
    search <arguments>    - Search database
    help   (command)      - Print help"
            }
            Some("scan") => {
                "Usage scan (type) <addresses>

Example: scan ping 127.0.0.0/8
Example: scan 12.34.0.0-12.34.56.78,127.0.0.1

scan a block of addresses using diffrent methods

- scan ping <addresses>
Scan a block of addresses and check if their online

- scan tcp <addresses>
Scan a block of addresses and check if their online, then scan and check what ports are open

- scan service <addresses>
Scan a block of addresses and check if their online, then scan to check what ports are open, then scan to check what services are running and record responses

- scan <addresses>
Same as scan service"
            }

            Some("search") => {
                "Usage: search <arguments>
Example: search ssh:raspbian
Example: search port:80,443 http-nginx https-nginx
Example: search port-8081 https:favicon
Example: search google
Example: search port=22,80,443

The format of the search is a list of tags that include the service or port followed by an equator, or a plain text search

There are four types of equators

\":\" or \"+\" - If the result contains an item
\"-\" - If the result does not contain an item
\"=\" - If the result is exactly equal to an item
\"!=\" - If the result is exactly not equal to an item

"
            }
            Some(_) => {
                print_help(None);
                "Invalid Command!"
            }
        }
    );
}
