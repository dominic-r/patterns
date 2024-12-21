# 🔒 Patterns – Automated OWASP CRS and Bad Bot Detection for Caddy, Nginx, and Apache  
Automate the scraping of **OWASP Core Rule Set (CRS)** patterns and convert them into **Caddy, Nginx, and Apache** WAF configurations.  

Additionally, **Bad Bot/User-Agent detection** is integrated to block malicious web crawlers and scrapers.  

> This project helps protect web servers against common web attacks like **SQL Injection (SQLi)**, **XSS**, **RCE**, **LFI**, and malicious bots – automatically updated and deployed!  

---

## 🚀 Project Overview  
- **🎯 Goal**: Automate OWASP CRS rule collection and generate WAF configs for **Caddy, Nginx, and Apache**.  
- **⚡ Automation**: GitHub Actions fetch rules **daily** and push updated configurations to the repository.  
- **🤖 Bad Bot Blocking**: Block harmful bots by generating WAF rules from **public bot lists**.  
- **📄 Output**: WAF `.conf` files categorized by attack type (SQLi, XSS, LFI) and bot lists.  

---

## 📂 Project Structure  
```
patterns/
├── waf_patterns/           # 🔧 Generated WAF config files
│   ├── caddy/              # Caddy WAF configs
│   ├── nginx/              # Nginx WAF configs
│   └── apache/             # Apache WAF configs (ModSecurity)
├── owasp.py                # 🕵️ OWASP scraper (fetch CRS rules)
├── owasp2caddy.py          # 🔄 Convert OWASP JSON to Caddy WAF configs
├── owasp2nginx.py          # 🔄 Convert OWASP JSON to Nginx WAF configs
├── owasp2apache.py         # 🔄 Convert OWASP JSON to Apache ModSecurity configs
├── badbots.py              # 🔄 Generate WAF configs to block bad bots
├── owasp_rules.json        # 📊 Fetched OWASP rules (raw)
├── requirements.txt        # 🔄 Required tools
└── .github/workflows/      # 🤖 GitHub Actions for automation
    └── update_patterns.yml
```

---

## 🛠️ How It Works  
### 🔹 1. Scraping OWASP Rules  
- `owasp.py` scrapes the latest OWASP CRS patterns from GitHub.  
- Pulls attack patterns for **SQLi**, **XSS**, **RCE**, **LFI** from OWASP CRS `.conf` files.  

### 🔹 2. Multi-Platform WAF Config Generation  
- **`owasp2caddy.py`** – Generates Caddy WAF configs using OWASP patterns.  
- **`owasp2nginx.py`** – Converts OWASP patterns into Nginx WAF rules.  
- **`owasp2apache.py`** – Converts OWASP rules into Apache **ModSecurity** configurations.  

### 🔹 3. Bad Bot/User-Agent Detection  
- `badbots.py` fetches **public bot lists** to block malicious crawlers.  
- Fallback lists ensure bot detection works even if the main source fails.  
- Generates `.conf` files for Caddy, Nginx, and Apache.  

### 🔹 4. Automation (GitHub Actions)  
- GitHub Actions fetch new rules and bot lists **daily at midnight**.  
- Automatically commits and pushes updated `.conf` files for all three platforms (Caddy, Nginx, Apache).  

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
python owasp2nginx.py
python owasp2apache.py
python badbots.py
```

---

## 🚀 Usage (Web Server Integration)  
### 🔹 1. Caddy WAF Integration  
```bash
sudo cp waf_patterns/caddy/*.conf /etc/caddy/
```
Add to **Caddyfile**:  
```caddy
import waf_patterns/caddy/*.conf
```
Reload Caddy:  
```bash
caddy reload
```

---

### 🔹 2. Nginx WAF Integration  
```bash
sudo cp waf_patterns/nginx/*.conf /etc/nginx/waf/
```
Modify Nginx config:  
```nginx
server {
    include /etc/nginx/waf/*.conf;
    location / {
        # Other configs...
    }
}
```
Reload Nginx:  
```bash
sudo nginx -s reload
```

---

### 🔹 3. Apache ModSecurity Integration  
```bash
sudo cp waf_patterns/apache/*.conf /etc/modsecurity.d/
```
Add to Apache config:  
```apache
IncludeOptional /etc/modsecurity.d/*.conf
```
Restart Apache:  
```bash
sudo systemctl restart apache2
```

---

## 🧩 Example Output (Bot Blocker – Nginx WAF)  
**Bot Blocking (waf_patterns/nginx/bots.conf)**:  
```nginx
map $http_user_agent $bad_bot {
    "~*AhrefsBot" 1;
    "~*SemrushBot" 1;
    "~*MJ12bot" 1;
    default 0;
}
if ($bad_bot) {
    return 403;
}
```

---

## 🤖 Automation (GitHub Workflow)  
The GitHub Action (`.github/workflows/update_patterns.yml`) automates updates:  
- 🕛 **Runs Daily at Midnight (UTC)**  
- 🎯 **Manual Trigger Available** (from GitHub Actions tab)  
- 🚀 **Pushes Updated WAF Files** to `waf_patterns/`  

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
- [Nginx](https://nginx.org/)  
- [Apache ModSecurity](https://modsecurity.org/)  
- [MIT License](https://opensource.org/licenses/MIT)  

---

## 🚨 Issues  
If you encounter any issues, please open a ticket in the [Issues Tab](https://github.com/your-username/patterns/issues).  
