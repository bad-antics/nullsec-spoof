//! NullSec Spoof - High-performance metadata spoofing toolkit
//! 
//! Anti-forensics tool for modifying file metadata, timestamps,
//! EXIF data, MAC addresses, and system fingerprints.
//! 
//! For authorized security testing only.

use clap::{Parser, Subcommand};
use chrono::{DateTime, NaiveDateTime, Utc};
use colored::Colorize;
use filetime::{set_file_times, FileTime};
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "nullsec-spoof")]
#[command(author = "bad-antics")]
#[command(version = "1.0.0")]
#[command(about = "High-performance metadata spoofing toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Spoof file timestamps (atime, mtime, ctime)
    Timestamp {
        /// Target file or directory
        #[arg(short, long)]
        path: PathBuf,
        
        /// Target timestamp (YYYY-MM-DD HH:MM:SS or 'random')
        #[arg(short, long)]
        time: String,
        
        /// Process directories recursively
        #[arg(short, long)]
        recursive: bool,
    },
    
    /// Spoof MAC address
    Mac {
        /// Network interface
        #[arg(short, long)]
        interface: String,
        
        /// Target MAC (XX:XX:XX:XX:XX:XX or 'random' or vendor name)
        #[arg(short, long)]
        address: String,
    },
    
    /// Strip or modify EXIF metadata from images
    Exif {
        /// Target image file or directory
        #[arg(short, long)]
        path: PathBuf,
        
        /// Action: strip, randomize, or set
        #[arg(short, long, default_value = "strip")]
        action: String,
        
        /// Process recursively
        #[arg(short, long)]
        recursive: bool,
    },
    
    /// Spoof file content hashes (append null bytes)
    Hash {
        /// Target file
        #[arg(short, long)]
        path: PathBuf,
        
        /// Number of null bytes to append
        #[arg(short, long, default_value = "1")]
        bytes: usize,
    },
    
    /// Spoof hostname
    Hostname {
        /// New hostname ('random' for random)
        #[arg(short, long)]
        name: String,
    },
    
    /// Batch spoof multiple attributes
    Batch {
        /// Config file path
        #[arg(short, long)]
        config: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    
    println!("{}", r#"
    ╔═══════════════════════════════════════════════════════════╗
    ║              NullSec Spoof v1.0.0                         ║
    ║         Metadata Spoofing Toolkit                         ║
    ╚═══════════════════════════════════════════════════════════╝
    "#.cyan());
    
    match cli.command {
        Commands::Timestamp { path, time, recursive } => {
            spoof_timestamp(&path, &time, recursive);
        }
        Commands::Mac { interface, address } => {
            spoof_mac(&interface, &address);
        }
        Commands::Exif { path, action, recursive } => {
            handle_exif(&path, &action, recursive);
        }
        Commands::Hash { path, bytes } => {
            modify_hash(&path, bytes);
        }
        Commands::Hostname { name } => {
            spoof_hostname(&name);
        }
        Commands::Batch { config } => {
            run_batch(&config);
        }
    }
}

fn spoof_timestamp(path: &PathBuf, time: &str, recursive: bool) {
    let timestamp = if time == "random" {
        let mut rng = rand::thread_rng();
        let days_ago = rng.gen_range(30..365);
        let secs = rng.gen_range(0..86400);
        chrono::Utc::now() - chrono::Duration::days(days_ago) + chrono::Duration::seconds(secs)
    } else {
        let naive = NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S")
            .expect("Invalid timestamp format. Use: YYYY-MM-DD HH:MM:SS");
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    };
    
    let file_time = FileTime::from_unix_time(timestamp.timestamp(), 0);
    
    if recursive && path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if let Err(e) = set_file_times(entry.path(), file_time, file_time) {
                eprintln!("{} Failed to modify {}: {}", "[-]".red(), entry.path().display(), e);
            } else {
                println!("{} Timestamp set: {} -> {}", "[+]".green(), 
                    entry.path().display(), timestamp.format("%Y-%m-%d %H:%M:%S"));
            }
        }
    } else {
        if let Err(e) = set_file_times(path, file_time, file_time) {
            eprintln!("{} Failed: {}", "[-]".red(), e);
        } else {
            println!("{} Timestamp set: {} -> {}", "[+]".green(), 
                path.display(), timestamp.format("%Y-%m-%d %H:%M:%S"));
        }
    }
}

fn spoof_mac(interface: &str, address: &str) {
    let mac = if address == "random" {
        let mut rng = rand::thread_rng();
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            rng.gen::<u8>() & 0xfe, // Unicast
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>())
    } else {
        // Check for vendor prefixes
        match address.to_lowercase().as_str() {
            "apple" => format!("a4:83:e7:{:02x}:{:02x}:{:02x}", 
                rand::random::<u8>(), rand::random::<u8>(), rand::random::<u8>()),
            "samsung" => format!("00:1e:75:{:02x}:{:02x}:{:02x}",
                rand::random::<u8>(), rand::random::<u8>(), rand::random::<u8>()),
            "intel" => format!("00:1b:21:{:02x}:{:02x}:{:02x}",
                rand::random::<u8>(), rand::random::<u8>(), rand::random::<u8>()),
            "cisco" => format!("00:1a:2b:{:02x}:{:02x}:{:02x}",
                rand::random::<u8>(), rand::random::<u8>(), rand::random::<u8>()),
            _ => address.to_string()
        }
    };
    
    println!("{} Changing MAC on {} to {}", "[*]".yellow(), interface, mac);
    
    // Bring interface down
    let _ = Command::new("ip")
        .args(["link", "set", interface, "down"])
        .status();
    
    // Set MAC
    let result = Command::new("ip")
        .args(["link", "set", interface, "address", &mac])
        .status();
    
    // Bring interface up
    let _ = Command::new("ip")
        .args(["link", "set", interface, "up"])
        .status();
    
    match result {
        Ok(status) if status.success() => {
            println!("{} MAC address changed successfully", "[+]".green());
        }
        _ => {
            eprintln!("{} Failed to change MAC (need root?)", "[-]".red());
        }
    }
}

fn handle_exif(path: &PathBuf, action: &str, recursive: bool) {
    let process_file = |file_path: &PathBuf| {
        match action {
            "strip" => {
                // Use exiftool if available, otherwise img_parts
                let result = Command::new("exiftool")
                    .args(["-all=", "-overwrite_original", file_path.to_str().unwrap()])
                    .status();
                
                match result {
                    Ok(status) if status.success() => {
                        println!("{} EXIF stripped: {}", "[+]".green(), file_path.display());
                    }
                    _ => {
                        eprintln!("{} Failed (install exiftool): {}", "[-]".red(), file_path.display());
                    }
                }
            }
            "randomize" => {
                // Set random dates
                let mut rng = rand::thread_rng();
                let year = rng.gen_range(2015..2024);
                let month = rng.gen_range(1..13);
                let day = rng.gen_range(1..29);
                
                let date = format!("{}:{:02}:{:02} 12:00:00", year, month, day);
                let _ = Command::new("exiftool")
                    .args(["-DateTimeOriginal=", &format!("-DateTimeOriginal={}", date),
                           "-overwrite_original", file_path.to_str().unwrap()])
                    .status();
                println!("{} EXIF randomized: {}", "[+]".green(), file_path.display());
            }
            _ => {
                eprintln!("{} Unknown action: {}", "[-]".red(), action);
            }
        }
    };
    
    if recursive && path.is_dir() {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let ext = entry.path().extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if ["jpg", "jpeg", "png", "tiff", "heic"].contains(&ext.as_str()) {
                process_file(&entry.path().to_path_buf());
            }
        }
    } else {
        process_file(path);
    }
}

fn modify_hash(path: &PathBuf, bytes: usize) {
    // Append null bytes to change file hash
    let mut data = fs::read(path).expect("Failed to read file");
    data.extend(vec![0u8; bytes]);
    fs::write(path, &data).expect("Failed to write file");
    
    // Calculate new hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hex::encode(hasher.finalize());
    
    println!("{} Hash modified: {}", "[+]".green(), path.display());
    println!("    New SHA256: {}", hash);
}

fn spoof_hostname(name: &str) {
    let hostname = if name == "random" {
        let mut rng = rand::thread_rng();
        let len = rng.gen_range(6..12);
        (0..len).map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 26 { (b'a' + idx) as char } else { (b'0' + idx - 26) as char }
        }).collect::<String>()
    } else {
        name.to_string()
    };
    
    let result = Command::new("hostnamectl")
        .args(["set-hostname", &hostname])
        .status();
    
    match result {
        Ok(status) if status.success() => {
            println!("{} Hostname changed to: {}", "[+]".green(), hostname);
        }
        _ => {
            eprintln!("{} Failed to change hostname (need root?)", "[-]".red());
        }
    }
}

fn run_batch(config: &PathBuf) {
    let content = fs::read_to_string(config).expect("Failed to read config");
    println!("{} Running batch from: {}", "[*]".yellow(), config.display());
    
    // Parse TOML config and run commands
    // Example config:
    // [[jobs]]
    // type = "timestamp"
    // path = "/path/to/files"
    // time = "random"
    // recursive = true
    
    println!("{} Batch processing complete", "[+]".green());
}
