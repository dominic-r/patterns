import os
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/nginx"))  # Source directory for WAF files
NGINX_WAF_DIR = Path(os.getenv("NGINX_WAF_DIR", "/etc/nginx/waf/"))  # Target directory
NGINX_CONF = Path(os.getenv("NGINX_CONF", "/etc/nginx/nginx.conf"))  # Nginx config file
INCLUDE_STATEMENT = "include /etc/nginx/waf/*.conf;"  # Include directive


def copy_waf_files():
    """
    Copy Nginx WAF configuration files to the target directory.
    """
    logging.info("Copying Nginx WAF patterns...")

    try:
        # Ensure the target directory exists
        NGINX_WAF_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {NGINX_WAF_DIR}")

        # Copy .conf files from source to target directory
        for conf_file in WAF_DIR.glob("*.conf"):
            dst_path = NGINX_WAF_DIR / conf_file.name

            if dst_path.exists():
                logging.warning(f"[!] File already exists: {dst_path}")
                continue

            try:
                subprocess.run(["cp", str(conf_file), str(dst_path)], check=True)
                logging.info(f"[+] Copied {conf_file} to {NGINX_WAF_DIR}")
            except subprocess.CalledProcessError as e:
                logging.error(f"[!] Failed to copy {conf_file}: {e}")
                raise
    except Exception as e:
        logging.error(f"[!] Error copying WAF files: {e}")
        raise


def update_nginx_conf():
    """
    Ensure the WAF include statement is present in the Nginx configuration file.
    """
    logging.info("Ensuring WAF patterns are included in nginx.conf...")

    try:
        # Read the current configuration
        with open(NGINX_CONF, "r") as f:
            config = f.read()

        # Append include statement if not present
        if INCLUDE_STATEMENT not in config:
            logging.info("Adding WAF include to nginx.conf...")
            with open(NGINX_CONF, "a") as f:
                f.write(f"\n{INCLUDE_STATEMENT}\n")
            logging.info("[+] WAF include statement added to nginx.conf.")
        else:
            logging.info("WAF already included in nginx.conf.")
    except Exception as e:
        logging.error(f"[!] Error updating Nginx configuration: {e}")
        raise


def reload_nginx():
    """
    Reload Nginx to apply the new WAF rules.
    """
    logging.info("Reloading Nginx to apply new WAF rules...")

    try:
        # Test Nginx configuration
        subprocess.run(["nginx", "-t"], check=True)
        logging.info("[+] Nginx configuration test passed.")

        # Reload Nginx
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        logging.info("[+] Nginx reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Nginx configuration test failed: {e}")
        raise
    except FileNotFoundError:
        logging.error("[!] 'nginx' or 'systemctl' command not found. Are you on a supported system?")
        raise
    except Exception as e:
        logging.error(f"[!] Error reloading Nginx: {e}")
        raise


def main():
    """
    Main function to execute the script.
    """
    try:
        copy_waf_files()
        update_nginx_conf()
        reload_nginx()
        logging.info("[✔] Nginx configured with latest WAF rules.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
