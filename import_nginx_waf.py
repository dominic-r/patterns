import os
import subprocess
import logging
from pathlib import Path
import shutil
import filecmp
import time

# --- Configuration ---
LOG_LEVEL = logging.INFO
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/nginx")).resolve()
NGINX_WAF_DIR = Path(os.getenv("NGINX_WAF_DIR", "/etc/nginx/waf/")).resolve()
NGINX_CONF = Path(os.getenv("NGINX_CONF", "/etc/nginx/nginx.conf")).resolve()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/etc/nginx/waf_backup/")).resolve()
INCLUDE_STATEMENT = "include /etc/nginx/waf/*.conf;"

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def copy_waf_files():
    """Copies WAF files, handling existing files, and creating backups."""
    logger.info("Copying Nginx WAF patterns...")

    NGINX_WAF_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    for conf_file in WAF_DIR.glob("*.conf"):
        dst_path = NGINX_WAF_DIR / conf_file.name

        try:
            if dst_path.exists() and filecmp.cmp(conf_file, dst_path, shallow=False):
                logger.info(f"Skipping {conf_file.name} (identical file exists).")
                continue

            if dst_path.exists():
                backup_path = BACKUP_DIR / f"{dst_path.name}.{int(time.time())}"
                logger.warning(f"Existing {dst_path.name} differs. Backing up to {backup_path}")
                shutil.copy2(dst_path, backup_path)

            shutil.copy2(conf_file, dst_path)
            logger.info(f"Copied {conf_file.name} to {dst_path}")

        except OSError as e:
            logger.error(f"Error copying {conf_file.name}: {e}")
            raise

def update_nginx_conf():
    """Ensures the include directive is inside an existing http block."""
    logger.info("Checking Nginx configuration for WAF include...")

    try:
        with open(NGINX_CONF, "r") as f:
            config_lines = f.readlines()

        include_present = any(INCLUDE_STATEMENT in line for line in config_lines)

        if include_present:
            logger.info("WAF include statement already present.")
            return

        http_start = -1
        http_end = -1

        for i, line in enumerate(config_lines):
            if "http {" in line:
                http_start = i
                break

        if http_start == -1:
            logger.error("No 'http' block found in nginx.conf. Check your config!")
            raise ValueError("Nginx config is missing an 'http' block.")

        for i in range(http_start + 1, len(config_lines)):
            if "}" in config_lines[i]:
                http_end = i
                break

        if http_end == -1:
            logger.error("Malformed nginx.conf: 'http' block is not closed properly.")
            raise ValueError("Malformed nginx.conf detected.")

        config_lines.insert(http_end, f"    {INCLUDE_STATEMENT}\n")

        with open(NGINX_CONF, "w") as f:
            f.writelines(config_lines)

        logger.info(f"Added WAF include to existing 'http' block in {NGINX_CONF}")

    except FileNotFoundError:
        logger.error(f"Nginx configuration file not found: {NGINX_CONF}")
        raise
    except OSError as e:
        logger.error(f"Error updating Nginx configuration: {e}")
        raise

def reload_nginx():
    """Tests and reloads Nginx if the config is valid."""
    logger.info("Testing Nginx configuration before reloading...")

    try:
        result = subprocess.run(["nginx", "-t"], capture_output=True, text=True, check=True)
        logger.info(f"Nginx configuration test successful:\n{result.stdout}")

        result = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, check=True)
        logger.info("Nginx reloaded successfully.")

    except subprocess.CalledProcessError as e:
        logger.critical(f"Nginx test/reload failed: {e.stderr}")
        raise SystemExit(1)
    except FileNotFoundError:
        logger.critical("'nginx' or 'systemctl' command not found. Is Nginx installed?")
        raise SystemExit(1)
    except Exception as e:
        logger.critical(f"Unexpected error while reloading Nginx: {e}")
        raise SystemExit(1)

def main():
    """Main function."""
    try:
        copy_waf_files()
        update_nginx_conf()
        reload_nginx()
        logger.info("Nginx WAF configuration updated successfully.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
