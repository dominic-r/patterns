import os
import subprocess
import logging
from pathlib import Path
import shutil
import filecmp  # Import for file comparison

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/apache")).resolve()
APACHE_WAF_DIR = Path(os.getenv("APACHE_WAF_DIR", "/etc/modsecurity.d/")).resolve()
APACHE_CONF = Path(os.getenv("APACHE_CONF", "/etc/apache2/apache2.conf")).resolve()
INCLUDE_STATEMENT = "IncludeOptional /etc/modsecurity.d/*.conf"
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/etc/modsecurity.d/backup")).resolve()


# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def copy_waf_files():
    """Copies WAF files, handling existing files and creating backups."""
    logger.info("Copying Apache WAF patterns...")

    # Ensure target directory exists
    APACHE_WAF_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Target directory: {APACHE_WAF_DIR}")

    # Ensure backup directory exists
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Backup directory: {BACKUP_DIR}")

    for conf_file in WAF_DIR.glob("*.conf"):
        dst_path = APACHE_WAF_DIR / conf_file.name

        try:
            if dst_path.exists():
                # Compare files.  If identical, skip.  If different, backup and replace.
                if filecmp.cmp(conf_file, dst_path, shallow=False):
                    logger.info(f"Skipping {conf_file.name} (identical file exists).")
                    continue  # Identical file, skip

                # Different file exists: create backup
                backup_path = BACKUP_DIR / f"{dst_path.name}.{int(time.time())}"  # Timestamped backup
                logger.warning(f"Existing file {dst_path.name} differs. Backing up to {backup_path}")
                shutil.copy2(dst_path, backup_path)  # Backup existing file

            # Copy the new file (or overwrite if it was different)
            shutil.copy2(conf_file, dst_path)  # Copy with metadata
            logger.info(f"Copied {conf_file.name} to {dst_path}")

        except OSError as e:
            logger.error(f"Error copying {conf_file.name}: {e}")
            raise  # Re-raise for critical error handling


def update_apache_conf():
    """Ensures the include statement is present, avoiding duplicates."""
    logger.info("Checking Apache configuration for WAF include...")

    try:
        with open(APACHE_CONF, "r") as f:
            config_lines = f.readlines()

        # Check if the include statement *already* exists.
        include_present = any(INCLUDE_STATEMENT in line for line in config_lines)

        if not include_present:
            # Append the include statement to the *end* of the file.
            with open(APACHE_CONF, "a") as f:
                f.write(f"\n{INCLUDE_STATEMENT}\n")  # Add a newline for safety
            logger.info(f"Added include statement to {APACHE_CONF}")
        else:
            logger.info("Include statement already present.")

    except FileNotFoundError:
        logger.error(f"Apache configuration file not found: {APACHE_CONF}")
        raise  # Critical error
    except OSError as e:
        logger.error(f"Error updating Apache configuration: {e}")
        raise


def reload_apache():
    """Tests the Apache configuration and reloads if valid."""
    logger.info("Reloading Apache...")

    try:
        # Test configuration
        subprocess.run(["apachectl", "configtest"], check=True, capture_output=True, text=True)
        logger.info("Apache configuration test successful.")

        # Reload Apache
        subprocess.run(["systemctl", "reload", "apache2"], check=True, capture_output=True, text=True)
        logger.info("Apache reloaded.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Apache command failed: {e.cmd} - Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise  # Re-raise to signal failure
    except FileNotFoundError:
        logger.error("apachectl or systemctl command not found.  Is Apache/systemd installed?")
        raise


def main():
    """Main function."""
    try:
        copy_waf_files()
        update_apache_conf()
        reload_apache()
        logger.info("Apache WAF configuration updated successfully.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
