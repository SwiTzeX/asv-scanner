# 🔍 ASV PCI DSS Security Scanner

A multi-threaded security scanner that checks for:
- Open ports and known CVEs (via Nmap & CVE API)
- SSL/TLS security (certificates, weak ciphers)
- DNS zone transfers, SMTP open relays, ICMP exposure
- Web application security (external scripts, ZAP scan)
- PCI DSS-compliant reporting (JSON + console summary)

---

## 📦 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run

Inside the `asv-scanner` folder, run:

```bash
python3 main.py
```

Then enter your **target domain or IP address** when prompted.

Example:
```bash
Enter Target IP or Domain: example.com
```

---

## 📝 Output

- Full PCI DSS scan summary is printed in the console
- A detailed report is saved as:
  ```
  pci_asv_scan_report.json
  ```

---

## 📁 Project Structure

```
scanner/
├── main.py                 # Entry point
├── config.py               # Global constants
├── core/                   # Scanning & reporting logic
│   ├── port_scanner.py
│   ├── report.py
│   └── result_manager.py
├── utils/                  # Helper tools
│   ├── tls_scanner.py
│   ├── cve_api.py
│   ├── dns_smtp_icmp.py
│   ├── passive_web.py
│   └── zap_scanner.py
├── requirements.txt
```

---

## ⚠️ Notes

- Requires **Nmap** installed on your system.
- Make sure OWASP ZAP is running at `http://127.0.0.1:8080` if using active scan.
- Works best on **Linux-based OS** (Ubuntu, Kali, etc.)

---

## 📖 License

MIT — do what you want, just give credit if it helps. 🙂