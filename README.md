<div align="center">

# 🎭 NullSec Spoof

[![Rust](https://img.shields.io/badge/Rust-1.75+-f85149?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-3fb950?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-58a6ff?style=for-the-badge)](https://github.com/bad-antics/nullsec-spoof)

**High-Performance Metadata Spoofing Toolkit**

*Anti-forensics • Privacy • Evasion • Covert Operations*

</div>

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| ⏰ **Timestamp Spoofing** | Modify atime, mtime, ctime on files |
| 🔗 **MAC Spoofing** | Randomize or vendor-spoof MAC addresses |
| 📷 **EXIF Stripping** | Remove or randomize image metadata |
| #️⃣ **Hash Modification** | Alter file hashes without visible changes |
| 🖥️ **Hostname Spoofing** | Randomize system hostname |
| 📦 **Batch Processing** | Config-driven bulk operations |

## 🚀 Installation

```bash
# From source
cargo install --path .

# Or build release
cargo build --release
./target/release/nullsec-spoof --help
```

## 📖 Usage

### Timestamp Spoofing
```bash
# Set specific timestamp
nullsec-spoof timestamp -p /path/to/file -t "2023-06-15 14:30:00"

# Random timestamp (30-365 days ago)
nullsec-spoof timestamp -p /path/to/dir -t random -r

# Recursive directory
nullsec-spoof timestamp -p /evidence -t "2022-01-01 00:00:00" -r
```

### MAC Address Spoofing
```bash
# Random MAC
nullsec-spoof mac -i wlan0 -a random

# Vendor-specific (Apple, Samsung, Intel, Cisco)
nullsec-spoof mac -i eth0 -a apple

# Specific MAC
nullsec-spoof mac -i wlan0 -a "00:11:22:33:44:55"
```

### EXIF Metadata
```bash
# Strip all EXIF data
nullsec-spoof exif -p photo.jpg -a strip

# Randomize dates
nullsec-spoof exif -p /photos -a randomize -r

# Process entire directory
nullsec-spoof exif -p /images -a strip -r
```

### Hash Modification
```bash
# Append null bytes to change hash
nullsec-spoof hash -p malware.exe -b 1
```

### Hostname Spoofing
```bash
# Random hostname
nullsec-spoof hostname -n random

# Specific hostname
nullsec-spoof hostname -n "workstation-42"
```

## 🔒 Security Notes

- Requires root for MAC and hostname changes
- Changes persist across sessions for hostname
- Use responsibly for authorized testing only

---

<div align="center">

**[bad-antics](https://github.com/bad-antics)** • Part of [NullSec Linux](https://github.com/bad-antics/nullsec-linux)

</div>
