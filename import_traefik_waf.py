import os
import subprocess
import logging
from pathlib import Path
import shutil
import filecmp
import time
import toml  # Add toml library

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/traefik")).resolve()
TRAEFIK_WAF_DIR = Path(os.getenv("TRAEFIK_WAF_DIR", "/etc/traefik/waf/")).resolve()
TRAEFIK_DYNAMIC_CONF = Path(os.getenv("TRAEFIK_DYNAMIC_CONF", "/etc/traefik/dynamic.toml")).resolve()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/etc/traefik/waf_backup/")).resolve()
# No longer a simple string; will be constructed dynamically
# INCLUDE_STATEMENT = 'middlewares = ["bad_bot_block"]'

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)



def copy_waf_files():
    """Copies WAF files, handling existing files and creating backups."""
    logger.info("Copying Traefik WAF patterns...")

    TRAEFIK_WAF_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    for toml_file in WAF_DIR.glob("*.toml"):  # Find all .toml files
        dst_path = TRAEFIK_WAF_DIR / toml_file.name

        try:
            if dst_path.exists():
                # Compare and backup if different
                if filecmp.cmp(toml_file, dst_path, shallow=False):
                    logger.info(f"Skipping {toml_file.name} (identical file exists).")
                    continue
                # Backup different file
                backup_path = BACKUP_DIR / f"{dst_path.name}.{int(time.time())}"
                logger.warning(f"Existing {dst_path.name} differs. Backing up to {backup_path}")
                shutil.copy2(dst_path, backup_path)

            # Copy the (new/updated) file
            shutil.copy2(toml_file, dst_path)
            logger.info(f"Copied {toml_file.name} to {dst_path}")

        except OSError as e:
            logger.error(f"Error copying {toml_file.name}: {e}")
            raise

def update_traefik_conf():
    """
    Ensures Traefik's dynamic config includes the generated middlewares.
    This function now *intelligently* adds the middlewares to a router,
    creating the necessary sections if they don't exist.  It also avoids
    duplicate middleware entries.
    """
    logger.info("Updating Traefik dynamic configuration...")

    try:
        # Create dynamic_conf.toml if it doesn't exist.
        if not TRAEFIK_DYNAMIC_CONF.exists():
            TRAEFIK_DYNAMIC_CONF.parent.mkdir(parents=True, exist_ok=True)
            # Initialize with empty http section
            with open(TRAEFIK_DYNAMIC_CONF, "w") as f:
                f.write("[http]\n  [http.middlewares]\n  [http.routers]\n    [http.routers.default]\n      rule = \"PathPrefix(`/`)\"\n      service = \"default-service\"\n") # added default service to make it work
            logger.info(f"Created initial dynamic config file: {TRAEFIK_DYNAMIC_CONF}")


        # Load existing TOML configuration (if any).
        try:
            config = toml.load(TRAEFIK_DYNAMIC_CONF)
        except toml.TomlDecodeError as e:
            logger.error(f"Error decoding TOML file {TRAEFIK_DYNAMIC_CONF}: {e}")
            raise

        # 1. Collect *all* middleware names from the generated file.
        middleware_names = []
        middleware_file = TRAEFIK_WAF_DIR / "middleware.toml"
        if middleware_file.exists():
            try:
                middleware_config = toml.load(middleware_file)
                if "http" in middleware_config and "middlewares" in middleware_config["http"]:
                    middleware_names = list(middleware_config["http"]["middlewares"].keys())
            except toml.TomlDecodeError as e:
                logger.error(f"Error reading generated middleware file: {e}")
                # Don't raise here; we can still try to proceed

        if not middleware_names:
            logger.warning("No middlewares found in generated file. Skipping configuration update.")
            return # added return to avoid errors

        # 2.  Ensure the necessary sections exist in the dynamic config.
        if "http" not in config:
            config["http"] = {}
        if "routers" not in config["http"]:
            config["http"]["routers"] = {}
        if "my_router" not in config["http"]["routers"]:  # Use a specific router name
            config["http"]["routers"]["my_router"] = {
                "rule": "PathPrefix(`/`)",  # Default rule - adjust as needed!
                "service": "my_service",    # Default service - MUST BE DEFINED!
                "middlewares": [],
            }
        # check default values exists
        if "rule" not in config["http"]["routers"]["my_router"]:
            config["http"]["routers"]["my_router"]["rule"] = "PathPrefix(`/`)"
        if "service" not in config["http"]["routers"]["my_router"]:
            config["http"]["routers"]["my_router"]["service"] = "my_service" # needs to have a service

        # 3. Add middlewares to the router's 'middlewares' list, avoiding duplicates
        existing_middlewares = config["http"]["routers"]["my_router"].get("middlewares", [])
        for middleware_name in middleware_names:
            if middleware_name not in existing_middlewares:
                existing_middlewares.append(middleware_name)
        config["http"]["routers"]["my_router"]["middlewares"] = existing_middlewares

        # 4. Write the updated configuration back to the file.
        try:
            with open(TRAEFIK_DYNAMIC_CONF, "w") as f:
                toml.dump(config, f)
            logger.info(f"Updated Traefik dynamic configuration: {TRAEFIK_DYNAMIC_CONF}")
        except OSError as e:
            logger.error(f"Error writing to {TRAEFIK_DYNAMIC_CONF}: {e}")
            raise

    except Exception as e:  # Catch broader exception during file ops
        logger.error(f"Error updating Traefik dynamic configuration: {e}")
        raise

def reload_traefik():
    """Tests the Traefik configuration (if possible) and reloads."""
    logger.info("Reloading Traefik...")

    try:
        # Traefik doesn't have a built-in config test like nginx or apachectl.
        # We'll rely on systemctl to do a basic check during reload.

        # Reload Traefik
        result = subprocess.run(["systemctl", "reload", "traefik"],
                                capture_output=True, text=True, check=True)
        logger.info("Traefik reloaded.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Traefik command failed: {e.cmd} - Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise
    except FileNotFoundError:
        logger.error("'systemctl' command not found. Is systemd installed?")
        raise


def main():
    """Main function."""
    try:
        copy_waf_files()
        update_traefik_conf()
        reload_traefik()
        logger.info("Traefik WAF configuration updated successfully.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
