import os
import subprocess
import logging
from pathlib import Path  # Better path handling
import shutil  # Safer file operations

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

# Constants (configurable via environment variables or command-line arguments)
WAF_DIR = os.getenv("WAF_DIR", "waf_patterns/traefik")  # Source directory for WAF files
TRAEFIK_WAF_DIR = os.getenv("TRAEFIK_WAF_DIR", "/etc/traefik/waf/")  # Target directory
TRAEFIK_DYNAMIC_CONF = os.getenv("TRAEFIK_DYNAMIC_CONF", "/etc/traefik/dynamic_conf.toml")  # Dynamic config file
INCLUDE_STATEMENT = '[[http.routers]]\n  rule = "PathPrefix(`/`)'  # Configuration to check/append

# Ensure paths are absolute and normalized
WAF_DIR = Path(WAF_DIR).resolve()
TRAEFIK_WAF_DIR = Path(TRAEFIK_WAF_DIR).resolve()
TRAEFIK_DYNAMIC_CONF = Path(TRAEFIK_DYNAMIC_CONF).resolve()


def copy_waf_files():
    """
    Copy WAF pattern files (middleware.toml and bots.toml) to the Traefik WAF directory.
    """
    logging.info("Copying Traefik WAF patterns...")

    try:
        # Ensure the target directory exists
        TRAEFIK_WAF_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {TRAEFIK_WAF_DIR}")

        # Copy middleware and bot files
        for file in ["middleware.toml", "bots.toml"]:
            src_path = WAF_DIR / file
            dst_path = TRAEFIK_WAF_DIR / file

            if src_path.exists():
                shutil.copy2(src_path, dst_path)  # Safer copy with metadata preservation
                logging.info(f"[+] {file} copied to {TRAEFIK_WAF_DIR}")
            else:
                logging.warning(f"[!] {file} not found in {WAF_DIR}")
    except Exception as e:
        logging.error(f"[!] Error copying WAF files: {e}")
        raise  # Re-raise the exception to halt execution


def update_traefik_conf():
    """
    Ensure WAF patterns are referenced in Traefik's dynamic configuration file.
    """
    logging.info("Ensuring WAF patterns are referenced in dynamic_conf.toml...")

    try:
        # Create dynamic_conf.toml if it doesn't exist
        if not TRAEFIK_DYNAMIC_CONF.exists():
            TRAEFIK_DYNAMIC_CONF.parent.mkdir(parents=True, exist_ok=True)
            with TRAEFIK_DYNAMIC_CONF.open("w") as f:
                f.write("[http.middlewares]\n")
            logging.info(f"[+] Created {TRAEFIK_DYNAMIC_CONF}")

        # Read the current configuration
        with TRAEFIK_DYNAMIC_CONF.open("r") as f:
            config = f.read()

        # Append middleware reference if not present
        if INCLUDE_STATEMENT not in config:
            logging.info("Adding WAF middleware to dynamic_conf.toml...")
            with TRAEFIK_DYNAMIC_CONF.open("a") as f:
                f.write(
                    f'\n[[http.routers]]\n'
                    f'  rule = "PathPrefix(`/`)"\n'
                    f'  service = "traefik"\n'
                    f'  middlewares = ["bad_bot_block"]\n'
                )
            logging.info("[+] WAF middleware added to dynamic_conf.toml.")
        else:
            logging.info("WAF middleware already referenced in dynamic_conf.toml.")
    except Exception as e:
        logging.error(f"[!] Error updating Traefik configuration: {e}")
        raise


def reload_traefik():
    """
    Reload the Traefik service to apply new WAF rules.
    """
    logging.info("Reloading Traefik to apply new WAF rules...")

    try:
        subprocess.run(["systemctl", "reload", "traefik"], check=True)
        logging.info("[+] Traefik reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] Failed to reload Traefik: {e}")
        raise
    except FileNotFoundError:
        logging.error("[!] 'systemctl' command not found. Are you on a systemd-based system?")
        raise


def main():
    """
    Main function to execute the script.
    """
    try:
        copy_waf_files()
        update_traefik_conf()
        reload_traefik()
        logging.info("[✔] Traefik configured with latest WAF rules.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
