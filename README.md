# 🔒 Patterns: OWASP CRS and Bad Bot Detection for Web Servers  

Automate the scraping of **OWASP Core Rule Set (CRS)** patterns and convert them into **Apache, Nginx, Traefik, and HAProxy** WAF configurations.  
Additionally, **Bad Bot/User-Agent detection** is integrated to block malicious web crawlers and scrapers.  

> 🚀 **Protect your servers against SQL Injection (SQLi), XSS, RCE, LFI, and malicious bots – with automated daily updates.**  

---

## 📌 Project Highlights  
- **🛡️ OWASP CRS Protection** – Leverages OWASP Core Rule Set for web application firewall (WAF) defense.  
- **🤖 Bad Bot Blocking** – Blocks known malicious bots using public bot lists.  
- **⚙️ Multi-Web Server Support** – Generates WAF configs for **Apache, Nginx, Traefik, and HAProxy**.  
- **🔄 Automatic Updates** – GitHub Actions fetch new rules **daily** and push updated configs.  
- **🧩 Scalable and Modular** – Easily extendable to support other web servers or load balancers.  

---

## 🌐 Supported Web Servers  
- **🔵 Nginx**  
- **🟠 Apache (ModSecurity)**  
- **🟣 Traefik**  
- **🔴 HAProxy**  

> [!NOTE]
> If you are using Caddy check the [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project.
---

## 📂 Project Structure  
```
patterns/
├── waf_patterns/           # 🔧 Generated WAF config files
│   ├── nginx/              # Nginx WAF configs
│   ├── apache/             # Apache WAF configs (ModSecurity)
│   ├── traefik/            # Traefik WAF configs
│   └── haproxy/            # HAProxy WAF configs
│── import_apache_waf.py
│── import_haproxy_waf.py
│── import_nginx_waf.py
│── import_traefik_waf.py
├── owasp.py                # 🕵️ OWASP scraper (fetch CRS rules)
├── owasp2nginx.py          # 🔄 Convert OWASP JSON to Nginx WAF configs
├── owasp2apache.py         # 🔄 Convert OWASP JSON to Apache ModSecurity configs
├── owasp2haproxy.py        # 🔄 Convert OWASP JSON to HAProxy WAF configs
├── badbots.py              # 🤖 Generate WAF configs to block bad bots
├── requirements.txt        # 📄 Required dependencies
└── .github/workflows/      # 🤖 GitHub Actions for automation
    └── update_patterns.yml
```

---

## 🛠️ How It Works  
### 🔹 1. Scraping OWASP Rules  
- **`owasp.py`** scrapes the latest OWASP CRS patterns from GitHub.  
- Extracts **SQLi, XSS, RCE, LFI** patterns from OWASP CRS `.conf` files.  

### 🔹 2. Generating WAF Configs for Each Platform  
- **`owasp2nginx.py`** – Generates **Nginx WAF** configurations.  
- **`owasp2apache.py`** – Outputs **Apache ModSecurity** rules.  
- **`owasp2traefik.py`** – Creates **Traefik WAF** rules.  
- **`owasp2haproxy.py`** – Builds **HAProxy ACL** files.  

### 🔹 3. Bad Bot/User-Agent Detection  
- **`badbots.py`** fetches public bot lists and generates bot-blocking configs.  
- Supports fallback lists to ensure reliable detection.  

---

## ⚙️ Installation  
**1. Clone the Repository:**  
```bash
git clone https://github.com/fabriziosalmi/patterns.git  
cd patterns
```

**2. Install Dependencies:**  
```bash
pip install -r requirements.txt
```

**3. Run Manually (Optional):**  
```bash
python owasp.py
python owasp2nginx.py
python owasp2apache.py
python owasp2haproxy.py
python owasp2traefik.py
python badbots.py
```

---

## 🚀 Usage (Web Server Integration)  
### 🔹 1. Nginx WAF Integration  
```bash
sudo python3 import_nginx_waf.py
```

### 🔹 2. Apache WAF Integration  
```bash
sudo python3 import_apache_waf.py
```

### 🔹 3. Traefik WAF Integration  
```bash
sudo python3 import_traefik_waf.py
```

### 🔹 4. HAProxy WAF Integration  
```bash
sudo python3 import_haproxy_waf.py
```

---

## 🔧 Example Output (Bot Blocker – Nginx)  
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
- **🕛 Daily Updates** – GitHub Actions fetch the latest OWASP CRS rules every day.  
- **🔄 Auto Deployment** – Pushes new `.conf` files directly to `waf_patterns/`.  
- **🎯 Manual Trigger** – Updates can also be triggered manually.  

---

## 🤝 Contributing  
1. **Fork** the repository.  
2. Create a **feature branch** (`feature/new-patterns`).  
3. **Commit** and push changes.  
4. Open a **Pull Request**.  

---

## 📄 License  
This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.  

---

## 📞 Need Help?  
- **Issues?** Open a ticket in the [Issues Tab](https://github.com/your-username/patterns/issues).  

---

## 🌐 Resources  
- [OWASP CRS](https://github.com/coreruleset/coreruleset)  
- [Apache ModSecurity](https://modsecurity.org/)  
- [Nginx](https://nginx.org/)  
- [Traefik](https://github.com/traefik/traefik)  
- [HaProxy](https://www.haproxy.org/)  
