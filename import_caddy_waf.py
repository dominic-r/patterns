import os
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

WAF_DIR = "waf_patterns/caddy"
CADDY_WAF_DIR = "/etc/caddy/waf/"
CADDY_CONF = "/etc/caddy/Caddyfile"
INCLUDE_STATEMENT = "import waf/*.conf"

def copy_waf_files():
    logging.info("Copying Caddy WAF patterns...")
    os.makedirs(CADDY_WAF_DIR, exist_ok=True)
    subprocess.run(["cp", "-R", f"{WAF_DIR}/*", CADDY_WAF_DIR], check=True)

def update_caddyfile():
    logging.info("Ensuring WAF patterns are imported in Caddyfile...")

    with open(CADDY_CONF, "r") as f:
        config = f.read()

    if INCLUDE_STATEMENT not in config:
        logging.info("Adding WAF import to Caddyfile...")
        with open(CADDY_CONF, "a") as f:
            f.write(f"\n{INCLUDE_STATEMENT}\n")
    else:
        logging.info("WAF patterns already imported in Caddyfile.")

def reload_caddy():
    logging.info("Reloading Caddy to apply new WAF rules...")
    subprocess.run(["caddy", "reload"], check=True)

if __name__ == "__main__":
    copy_waf_files()
    update_caddyfile()
    reload_caddy()
    logging.info("[✔] Caddy configured with latest WAF rules.")
