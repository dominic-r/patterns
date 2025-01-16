import os
import subprocess
import logging
from pathlib import Path
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables)
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/apache")).resolve()  # Source directory for WAF files
APACHE_WAF_DIR = Path(os.getenv("APACHE_WAF_DIR", "/etc/modsecurity.d/")).resolve()  # Target directory
APACHE_CONF = Path(os.getenv("APACHE_CONF", "/etc/apache2/apache2.conf")).resolve()  # Apache config file
INCLUDE_STATEMENT = "IncludeOptional /etc/modsecurity.d/*.conf"  # Include directive


def copy_waf_files():
    """
    Copy Apache WAF configuration files to the target directory.

    Raises:
        Exception: If there is an error copying files.
    """
    logging.info("Copying Apache WAF patterns...")

    try:
        # Ensure the target directory exists
        APACHE_WAF_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {APACHE_WAF_DIR}")

        # Copy .conf files from source to target directory
        for conf_file in WAF_DIR.glob("*.conf"):
            dst_path = APACHE_WAF_DIR / conf_file.name

            if dst_path.exists():
                logging.warning(f"[!] File already exists: {dst_path}")
                continue

            try:
                shutil.copy2(conf_file, dst_path)
                logging.info(f"[+] Copied {conf_file} to {APACHE_WAF_DIR}")
            except Exception as e:
                logging.error(f"[!] Failed to copy {conf_file}: {e}")
                raise
    except Exception as e:
        logging.error(f"[!] Error copying WAF files: {e}")
        raise


def update_apache_conf():
    """
    Ensure the WAF include statement is present in the Apache configuration file.

    Raises:
        Exception: If there is an error updating the Apache configuration.
    """
    logging.info("Ensuring WAF patterns are included in apache2.conf...")

    try:
        # Read the current configuration
        with open(APACHE_CONF, "r") as f:
            config = f.read()

        # Append include statement if not present
        if INCLUDE_STATEMENT not in config:
            logging.info("Adding WAF include to apache2.conf...")
            with open(APACHE_CONF, "a") as f:
                f.write(f"\n{INCLUDE_STATEMENT}\n")
            logging.info("[+] WAF include statement added to apache2.conf.")
        else:
            logging.info("WAF patterns already included in apache2.conf.")
    except Exception as e:
        logging.error(f"[!] Error updating Apache configuration: {e}")
        raise


def reload_apache():
    """
    Reload Apache to apply the new WAF rules.

    Raises:
        Exception: If there is an error reloading Apache.
    """
    logging.info("Reloading Apache to apply new WAF rules...")

    try:
        # Test Apache configuration
        subprocess.run(["apachectl", "configtest"], check=True)
        logging.info("[+] Apache configuration test passed.")

        # Reload Apache
        subprocess.run(["systemctl", "reload", "apache2"], check=True)
        logging.info("[+] Apache reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Apache configuration test failed: {e}")
        raise
    except FileNotFoundError:
        logging.error("[!] 'apachectl' or 'systemctl' command not found. Are you on a supported system?")
        raise
    except Exception as e:
        logging.error(f"[!] Error reloading Apache: {e}")
        raise


def main():
    """
    Main function to execute the script.
    """
    try:
        copy_waf_files()
        update_apache_conf()
        reload_apache()
        logging.info("[✔] Apache configured with latest WAF rules.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()