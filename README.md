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

### Example

```
fab@Mac patterns % python3 owasp.py
2025-01-03 13:22:52,744 - INFO - Latest matching tag: refs/tags/v4.0.0-rc2
2025-01-03 13:22:52,988 - INFO - Fetching REQUEST-901-INITIALIZATION.conf...
2025-01-03 13:22:53,164 - INFO - Fetching REQUEST-905-COMMON-EXCEPTIONS.conf...
2025-01-03 13:22:53,335 - INFO - Fetching REQUEST-911-METHOD-ENFORCEMENT.conf...
2025-01-03 13:22:53,513 - INFO - Fetching REQUEST-913-SCANNER-DETECTION.conf...
2025-01-03 13:22:53,683 - INFO - Fetching REQUEST-920-PROTOCOL-ENFORCEMENT.conf...
2025-01-03 13:22:53,892 - INFO - Fetching REQUEST-921-PROTOCOL-ATTACK.conf...
2025-01-03 13:22:54,057 - INFO - Fetching REQUEST-922-MULTIPART-ATTACK.conf...
2025-01-03 13:22:54,218 - INFO - Fetching REQUEST-930-APPLICATION-ATTACK-LFI.conf...
2025-01-03 13:22:54,388 - INFO - Fetching REQUEST-931-APPLICATION-ATTACK-RFI.conf...
2025-01-03 13:22:54,563 - INFO - Fetching REQUEST-932-APPLICATION-ATTACK-RCE.conf...
2025-01-03 13:22:54,784 - INFO - Fetching REQUEST-933-APPLICATION-ATTACK-PHP.conf...
2025-01-03 13:22:54,947 - INFO - Fetching REQUEST-934-APPLICATION-ATTACK-GENERIC.conf...
2025-01-03 13:22:55,150 - INFO - Fetching REQUEST-941-APPLICATION-ATTACK-XSS.conf...
2025-01-03 13:22:55,328 - INFO - Fetching REQUEST-942-APPLICATION-ATTACK-SQLI.conf...
2025-01-03 13:22:55,560 - INFO - Fetching REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf...
2025-01-03 13:22:55,750 - INFO - Fetching REQUEST-944-APPLICATION-ATTACK-JAVA.conf...
2025-01-03 13:22:55,922 - INFO - Fetching REQUEST-949-BLOCKING-EVALUATION.conf...
2025-01-03 13:22:56,106 - INFO - Fetching RESPONSE-950-DATA-LEAKAGES.conf...
2025-01-03 13:22:56,530 - INFO - Fetching RESPONSE-951-DATA-LEAKAGES-SQL.conf...
2025-01-03 13:22:56,705 - INFO - Fetching RESPONSE-952-DATA-LEAKAGES-JAVA.conf...
2025-01-03 13:22:57,088 - INFO - Fetching RESPONSE-953-DATA-LEAKAGES-PHP.conf...
2025-01-03 13:22:57,279 - INFO - Fetching RESPONSE-954-DATA-LEAKAGES-IIS.conf...
2025-01-03 13:22:57,454 - INFO - Fetching RESPONSE-955-WEB-SHELLS.conf...
2025-01-03 13:22:57,669 - INFO - Fetching RESPONSE-959-BLOCKING-EVALUATION.conf...
2025-01-03 13:22:57,842 - INFO - Fetching RESPONSE-980-CORRELATION.conf...
2025-01-03 13:22:58,006 - INFO - Fetched 646 rules.
2025-01-03 13:22:58,013 - INFO - Rules saved to owasp_rules.json.
2025-01-03 13:22:58,014 - INFO - All rules fetched and saved successfully.
```

```
fab@Mac patterns % python3 owasp2apache.py
2025-01-03 13:23:02,973 - INFO - [*] Loading OWASP rules...
2025-01-03 13:23:02,974 - INFO - [*] Generating Apache WAF configs from 646 rules...
2025-01-03 13:23:02,975 - INFO - [+] Generated waf_patterns/apache/initialization.conf (30 patterns)
2025-01-03 13:23:02,975 - INFO - [+] Generated waf_patterns/apache/exceptions.conf (5 patterns)
2025-01-03 13:23:02,975 - INFO - [+] Generated waf_patterns/apache/enforcement.conf (112 patterns)
2025-01-03 13:23:02,975 - INFO - [+] Generated waf_patterns/apache/detection.conf (9 patterns)
2025-01-03 13:23:02,976 - INFO - [+] Generated waf_patterns/apache/attack.conf (31 patterns)
2025-01-03 13:23:02,976 - INFO - [+] Generated waf_patterns/apache/lfi.conf (13 patterns)
2025-01-03 13:23:02,976 - INFO - [+] Generated waf_patterns/apache/rfi.conf (15 patterns)
2025-01-03 13:23:02,976 - INFO - [+] Generated waf_patterns/apache/rce.conf (54 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/php.conf (39 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/generic.conf (18 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/xss.conf (43 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/sqli.conf (73 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/fixation.conf (14 patterns)
2025-01-03 13:23:02,977 - INFO - [+] Generated waf_patterns/apache/java.conf (34 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/evaluation.conf (54 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/leakages.conf (11 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/sql.conf (25 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/iis.conf (13 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/shells.conf (34 patterns)
2025-01-03 13:23:02,978 - INFO - [+] Generated waf_patterns/apache/correlation.conf (19 patterns)
2025-01-03 13:23:02,978 - INFO - [✔] Apache ModSecurity configurations generated successfully.
```

```
fab@Mac patterns % python3 owasp2nginx.py
2025-01-03 13:23:06,134 - INFO - [*] Loading OWASP rules...
2025-01-03 13:23:06,135 - INFO - [*] Generating Nginx WAF configs from 646 rules...
2025-01-03 13:23:06,135 - INFO - [+] Generated waf_patterns/nginx/initialization.conf (30 patterns)
2025-01-03 13:23:06,135 - INFO - [+] Generated waf_patterns/nginx/exceptions.conf (5 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/enforcement.conf (112 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/detection.conf (9 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/attack.conf (31 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/lfi.conf (13 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/rfi.conf (15 patterns)
2025-01-03 13:23:06,136 - INFO - [+] Generated waf_patterns/nginx/rce.conf (54 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/php.conf (39 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/generic.conf (18 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/xss.conf (43 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/sqli.conf (73 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/fixation.conf (14 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/java.conf (34 patterns)
2025-01-03 13:23:06,137 - INFO - [+] Generated waf_patterns/nginx/evaluation.conf (54 patterns)
2025-01-03 13:23:06,138 - INFO - [+] Generated waf_patterns/nginx/leakages.conf (11 patterns)
2025-01-03 13:23:06,138 - INFO - [+] Generated waf_patterns/nginx/sql.conf (25 patterns)
2025-01-03 13:23:06,138 - INFO - [+] Generated waf_patterns/nginx/iis.conf (13 patterns)
2025-01-03 13:23:06,138 - INFO - [+] Generated waf_patterns/nginx/shells.conf (34 patterns)
2025-01-03 13:23:06,138 - INFO - [+] Generated waf_patterns/nginx/correlation.conf (19 patterns)
2025-01-03 13:23:06,138 - INFO - [✔] Nginx WAF configurations generated successfully.
```

```
fab@Mac patterns % python3 owasp2haproxy.py
2025-01-03 13:23:08,952 - INFO - [*] Loading OWASP rules...
2025-01-03 13:23:08,953 - INFO - [*] Generating HAProxy WAF configs from 646 rules...
2025-01-03 13:23:08,953 - INFO - [+] Created or verified directory: waf_patterns/haproxy
2025-01-03 13:23:08,954 - INFO - [+] HAProxy WAF rules generated at waf_patterns/haproxy/waf.acl
2025-01-03 13:23:08,954 - INFO - [✔] HAProxy WAF configurations generated successfully.
```

```
fab@Mac patterns % python3 owasp2traefik.py
[+] Traefik WAF rules generated at waf_patterns/traefik/middleware.toml
```


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
