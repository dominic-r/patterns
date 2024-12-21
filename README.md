# Patterns  
Automate the scraping of **OWASP Core Rule Set (CRS)** patterns and convert them into **Caddy web server WAF configurations**.  
This project helps protect Caddy servers against common web attacks like **SQL Injection (SQLi)**, **XSS**, **RCE**, and more – all with minimal effort!  

---

## 🚀 Project Overview  
- **🎯 Goal**: Automate OWASP CRS rule collection and generate Caddy WAF configs.  
- **⚡ Automation**: GitHub Actions fetch rules daily and push new configurations.  
- **📄 Output**: Caddy `.conf` files categorized by attack type (SQLi, XSS, LFI).  

---

## 📂 Project Structure  
```
patterns/
├── waf_patterns/           # 🔧 Generated Caddy WAF config files
│   ├── sql.conf            # SQL Injection patterns
│   ├── xss.conf            # XSS patterns
│   └── bots.conf           # Bot detection patterns
├── scrapers/
│   └── owasp.py            # 🕵️ OWASP scraper (fetch CRS rules)
├── owasp2caddy.py          # 🔄 Convert OWASP JSON to Caddy WAF configs
├── owasp_rules.json        # 📊 Fetched OWASP rules (raw)
└── .github/workflows/      # 🤖 GitHub Actions for automation
    └── update_patterns.yml
```

---

## 🛠️ How It Works  
### 🔹 1. Scraping OWASP Rules  
- `owasp.py` scrapes the latest OWASP CRS patterns from GitHub.  
- Pulls attack patterns for **SQLi**, **XSS**, **RCE**, **LFI** from OWASP CRS `.conf` files.  

### 🔹 2. Conversion to Caddy WAF  
- `owasp2caddy.py` converts OWASP patterns (`owasp_rules.json`) into **Caddy-compatible WAF** config files.  
- Output is stored in `waf_patterns/` by attack category.  

### 🔹 3. Automation (GitHub Actions)  
- GitHub Actions fetch new rules **daily at midnight**.  
- Updated rules are committed and pushed automatically to the repository.  

---

## ⚙️ Installation  
**1. Clone the Repository:**  
```bash
git clone https://github.com/your-username/patterns.git  
cd patterns
```

**2. Install Dependencies:**  
```bash
pip install -r requirements.txt
```

**3. Run Manually (Optional):**  
```bash
python owasp.py
python owasp2caddy.py
```

---

## 🚀 Usage (Caddy WAF Integration)  
**1. Copy the Generated `.conf` Files:**  
```bash
sudo cp waf_patterns/*.conf /etc/caddy/
```

**2. Import Patterns in Your Caddyfile:**  
```caddy
import waf_patterns/*.conf
```

**3. Reload Caddy:**  
```bash
caddy reload
```

---

## 🤖 Automation (GitHub Workflow)  
The GitHub Action (`.github/workflows/update_patterns.yml`) automates updates:  
- 🕛 **Runs Daily at Midnight (UTC)**  
- 🎯 **Manual Trigger Available** (from GitHub Actions tab)  
- 🚀 **Pushes Updated WAF Files** to `waf_patterns/`  

To enable:  
- Ensure the workflow file is active in your repository.  
- Updated patterns will automatically sync to the repo.  

---

## 🧩 Example Output (Caddy WAF)  
**SQL Injection Blocking (waf_patterns/sql.conf)**:  
```caddy
@block_sqli {
    path_regexp sqli "(?i)(union.*select|insert.*into|delete.*from|drop table)"
}
respond @block_sqli 403
```

**XSS Blocking (waf_patterns/xss.conf)**:  
```caddy
@block_xss {
    path_regexp xss "(?i)<.*script.*>|javascript:|alert\(.*\)"
}
respond @block_xss 403
```

---

## 🔧 Contributing  
1. Fork the repository.  
2. Create a feature branch (`feature/new-patterns`).  
3. Commit and push changes.  
4. Open a pull request (PR).  

---

## 📄 License  
This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.  

---

## 🌐 Resources  
- [OWASP CRS GitHub](https://github.com/coreruleset/coreruleset)  
- [Caddy Web Server](https://caddyserver.com/)  
- [MIT License](https://opensource.org/licenses/MIT)  

---

## 🚨 Issues  
If you encounter any issues, please open a ticket in the [Issues Tab](https://github.com/your-username/patterns/issues).  

