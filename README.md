# 🕵️ IOC Hunter with VirusTotal Integration

**IOC Hunter** is a Python-based CLI tool that helps security analysts enrich Indicators of Compromise (IOCs) using the [VirusTotal API](https://www.virustotal.com/). It supports file hashes, IP addresses, and URLs, providing detection stats and reputation data in CSV or JSON format.

---

## 🚀 Features

- Accepts IOCs from a file (hashes, IPs, URLs)
- Queries VirusTotal API for threat intelligence
- Outputs results in JSON or CSV
- Handles rate limiting and API errors
- Normalizes `hxxp://` to `http://` for safe IOC input
- Supports IP, URL, and file hash lookups

---

## 🛠️ Setup

### 1. Clone the Repository

```bash
git clone https://github.com/n-hirsch/ioc_hunter.git
cd ioc-hunter
```

### 2. Install Requirements

```bash
pip install requests
```

### 3. Configure API Key

Edit `ioc_hunter.py` and replace:

```python
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
```

Get your key from: https://www.virustotal.com/gui/join-us

---

## 📥 IOC Input File

Create a plain text file (e.g., `iocs.txt`) with one IOC per line:

```
8.8.8.8
1.1.1.1
hxxp://testphp.vulnweb.com
44d88612fea8a8f36de82e1278abb02f
```

---

## ⚙️ Usage

```bash
python ioc_hunter.py -f iocs.txt -o results.csv --format csv
```

### Arguments

| Argument       | Description                           |
|----------------|---------------------------------------|
| `-f` / `--file` | Path to file containing IOCs          |
| `-o` / `--output` | Output file name (default: results.json) |
| `--format`     | Output format: `csv` or `json`        |

---

## 📊 Output Example (CSV)

| ioc                              | type | reputation | harmless_votes | malicious_votes |
|----------------------------------|------|------------|----------------|------------------|
| 8.8.8.8                          | ip   | 1          | 10             | 1                |
| http://testphp.vulnweb.com      | url  | 0          | 3              | 2                |
| 44d88612fea8a8f36de82e1278abb02f | hash | -1         | 0              | 67               |

---

## ⚠️ Notes

- **Rate Limits:** Public VirusTotal API allows 4 requests/minute. Script uses `time.sleep(16)` between requests.
- **Not Found IOCs:** If an IOC has no entry in VirusTotal, it will be logged as a `404` but the script continues.

---

## 📄 License

MIT License

---

## 👤 Author

**Noah Hirsch**  
[https://github.com/n-hirsch]
