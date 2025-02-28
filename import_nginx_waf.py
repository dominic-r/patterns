import os
import subprocess
import logging
from pathlib import Path
import shutil
import filecmp
import time

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
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
            if dst_path.exists():
                # Compare and backup if different
                if filecmp.cmp(conf_file, dst_path, shallow=False):
                    logger.info(f"Skipping {conf_file.name} (identical file exists).")
                    continue
                # Backup different file
                backup_path = BACKUP_DIR / f"{dst_path.name}.{int(time.time())}"
                logger.warning(f"Existing {dst_path.name} differs. Backing up to {backup_path}")
                shutil.copy2(dst_path, backup_path)

            # Copy the (new/updated) file
            shutil.copy2(conf_file, dst_path)
            logger.info(f"Copied {conf_file.name} to {dst_path}")

        except OSError as e:
            logger.error(f"Error copying {conf_file.name}: {e}")
            raise


def update_nginx_conf():
    """Ensures the include directive is present in nginx.conf (http context)."""
    logger.info("Checking Nginx configuration for WAF include...")

    try:
        with open(NGINX_CONF, "r") as f:
            config_lines = f.readlines()

        # Check if the include statement is already present.
        include_present = any(INCLUDE_STATEMENT in line for line in config_lines)

        if not include_present:
            # Find the 'http' block.  This is where the include belongs.
            http_start = -1
            for i, line in enumerate(config_lines):
                if line.strip().startswith("http {"):
                    http_start = i
                    break

            if http_start == -1:
                # No http block found.  Add the include *and* the http block.
                logger.warning("No 'http' block found. Adding to end of file.")
                with open(NGINX_CONF, "a") as f:
                    f.write(f"\nhttp {{\n    {INCLUDE_STATEMENT}\n}}\n")
                logger.info(f"Added 'http' block and WAF include to {NGINX_CONF}")
                return

            # Find the end of the 'http' block
            http_end = -1
            for i in range(http_start + 1, len(config_lines)):
                if line.strip() == "}":
                     http_end = i
                     break

            if http_end == -1:
                # Malformed config?  Shouldn't happen, but handle it.
                http_end = len(config_lines)
                logger.warning("Malformed Nginx config (no closing brace for 'http' block).")

            # Insert the include statement *within* the http block.
            config_lines.insert(http_end, f"    {INCLUDE_STATEMENT}\n")

            # Write the modified configuration back.
            with open(NGINX_CONF, "w") as f:
                f.writelines(config_lines)
            logger.info(f"Added WAF include to 'http' block in {NGINX_CONF}")

        else:
            logger.info("WAF include statement already present.")

    except FileNotFoundError:
        logger.error(f"Nginx configuration file not found: {NGINX_CONF}")
        raise
    except OSError as e:
        logger.error(f"Error updating Nginx configuration: {e}")
        raise


def reload_nginx():
    """Tests the Nginx configuration and reloads if valid."""
    logger.info("Reloading Nginx...")

    try:
        # Test configuration
        result = subprocess.run(["nginx", "-t"],
                                capture_output=True, text=True, check=True)
        logger.info(f"Nginx configuration test successful:\n{result.stdout}")

        # Reload Nginx
        result = subprocess.run(["systemctl", "reload", "nginx"],
                                capture_output=True, text=True, check=True)
        logger.info("Nginx reloaded.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Nginx command failed: {e.cmd} - Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise  # Re-raise to signal failure
    except FileNotFoundError:
        logger.error("'nginx' or 'systemctl' command not found. Is Nginx/systemd installed?")
        raise
    except Exception as e: # added extra exception
        logger.error(f"[!] Error reloading Nginx: {e}")
        raise


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
