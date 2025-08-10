# 🧰 AFC - Artifact Forensics Collector

**AFC** is a Go-based tool designed to analyze, convert, and export key Windows forensic artifacts into structured CSV files.  
It supports a wide range of formats including `EVTX`, `Registry Hives`, `Prefetch`, `Scheduled Tasks`, `JumpList`, `MFT`, `Recycle Bin`, `LNK`, `PowerShell History`, and more.

---

## ✨ Main Features

- 🔍 Automatic detection of forensic files inside the given directory
- 🗃️ Parsing and normalization into clean `CSV` outputs
- ⚙️ Modular plugin support for specific artifact types
- 🧩 Compatible with artifacts extracted from DFIR toolkits (e.g., KAPE, Velociraptor)
- ☁️ Optional future support for upload to Wazuh Manager via configuration

---

## 📦 Supported Artifacts

- Prefetch (`.pf`)
- Event Logs (`.evtx`)
- Registry (`SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY`, `NTUSER.DAT`)
- Jump Lists (`.automaticDestinations-ms`, `.customDestinations-ms`)
- PowerShell Console History
- Scheduled Tasks (`.job`, `.xml`)
- Recycle Bin (`$I`, `$R`)
- MFT (Master File Table)
- LNK (Shell Link)
- UsnJrnl

---

## ⚙️ Configuration

The tool can be optionally configured via a `config.yaml` file.

### 🔧 Example `config.yaml`

```yaml
wazuh:
  manager_ip: "192.168.1.100"
  manager_port: 55000
  protocol: "http"  
  api_endpoint: "https://192.168.1.100:55000/api/v1/ingest"
  token: "xxxxxxxxxx"  
  verify_ssl: false
paths:
  input: "./data"
```

Place the file at the root of the project. Configuration is optional but recommended for SIEM integration.

---

## 🚀 Usage

1. Clone the project or download it:

```bash
git clone https://github.com/your-username/afc.git
cd afc
```

2. Place the forensic data inside the `./data/` directory.  
   You can paste the full folder structure exported by tools like **KAPE** or others.

3. (Optional) Add your `config.yaml` file to customize behavior.

4. Run the tool:

```bash
go run .
```

5. The resulting data will be saved temp in memory and as soon as possible send to the given wazuh endpoint.


## 🤖 Requirements

- Go 1.20 or newer
- Linux, macOS or Windows
- Run `go mod tidy` to fetch all Go module dependencies

---

## 🛡️ Forensic Safety

- AFC **does not modify original files**
- Works in **read-only** mode
- Supports low-level raw binary parsing
- Designed for **incident response**, **hunting**, and **triage** scenarios

---

## 📬 Contact

👨‍💻 **Author**: Guglielmo Borgognoni  
🐛 **Issues**: [Open on GitHub](https://github.com/bubu-gigi/afc/issues)