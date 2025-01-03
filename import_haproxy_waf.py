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
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/haproxy"))  # Source directory for WAF files
HAPROXY_WAF_DIR = Path(os.getenv("HAPROXY_WAF_DIR", "/etc/haproxy/waf/"))  # Target directory
HAPROXY_CONF = Path(os.getenv("HAPROXY_CONF", "/etc/haproxy/haproxy.cfg"))  # HAProxy config file

# HAProxy WAF configuration snippet
WAF_CONFIG_SNIPPET = """
# WAF and Bot Protection
frontend http-in
    bind *:80
    default_backend web_backend
    acl bad_bot hdr_sub(User-Agent) -i waf/bots.acl
    acl waf_attack path_reg waf/waf.acl
    http-request deny if bad_bot
    http-request deny if waf_attack
"""


def copy_waf_files():
    """
    Copy HAProxy WAF ACL files to the target directory.
    """
    logging.info("Copying HAProxy WAF patterns...")

    try:
        # Ensure the target directory exists
        HAPROXY_WAF_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"[+] Created or verified directory: {HAPROXY_WAF_DIR}")

        # Copy ACL files
        for file in ["bots.acl", "waf.acl"]:
            src_path = WAF_DIR / file
            dst_path = HAPROXY_WAF_DIR / file

            if not src_path.exists():
                logging.warning(f"[!] {file} not found in {WAF_DIR}")
                continue

            try:
                subprocess.run(["cp", str(src_path), str(dst_path)], check=True)
                logging.info(f"[+] {file} copied to {HAPROXY_WAF_DIR}")
            except subprocess.CalledProcessError as e:
                logging.error(f"[!] Failed to copy {file}: {e}")
                raise
    except Exception as e:
        logging.error(f"[!] Error copying WAF files: {e}")
        raise


def update_haproxy_conf():
    """
    Ensure the WAF configuration snippet is included in haproxy.cfg.
    """
    logging.info("Ensuring WAF patterns are included in haproxy.cfg...")

    try:
        # Read the current configuration
        with open(HAPROXY_CONF, "r") as f:
            config = f.read()

        # Append WAF configuration snippet if not present
        if WAF_CONFIG_SNIPPET.strip() not in config:
            logging.info("Adding WAF rules to haproxy.cfg...")
            with open(HAPROXY_CONF, "a") as f:
                f.write(WAF_CONFIG_SNIPPET)
            logging.info("[+] WAF rules added to haproxy.cfg.")
        else:
            logging.info("WAF patterns already included in haproxy.cfg.")
    except Exception as e:
        logging.error(f"[!] Error updating HAProxy configuration: {e}")
        raise


def reload_haproxy():
    """
    Reload HAProxy to apply the new WAF rules.
    """
    logging.info("Testing HAProxy configuration...")

    try:
        # Test HAProxy configuration
        subprocess.run(["haproxy", "-c", "-f", str(HAPROXY_CONF)], check=True)
        logging.info("[+] HAProxy configuration test passed.")

        # Reload HAProxy
        subprocess.run(["systemctl", "reload", "haproxy"], check=True)
        logging.info("[+] HAProxy reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[!] HAProxy configuration test failed: {e}")
        raise
    except FileNotFoundError:
        logging.error("[!] 'haproxy' or 'systemctl' command not found. Are you on a supported system?")
        raise
    except Exception as e:
        logging.error(f"[!] Error reloading HAProxy: {e}")
        raise


def main():
    """
    Main function to execute the script.
    """
    try:
        copy_waf_files()
        update_haproxy_conf()
        reload_haproxy()
        logging.info("[✔] HAProxy configured with latest WAF rules.")
    except Exception as e:
        logging.critical(f"[!] Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
