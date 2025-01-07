import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

INPUT_FILE = Path(os.getenv("INPUT_FILE", "owasp_rules.json"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "waf_patterns/nginx"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_owasp_rules(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Input file not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in file: {file_path}")
        raise


def validate_regex(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def sanitize_pattern(pattern):
    if "@pmFromFile" in pattern or "!@eq" in pattern or "!@within" in pattern or "@lt" in pattern:
        logging.warning(f"Skipping unsupported pattern: {pattern}")
        return None

    if pattern.startswith("@rx "):
        sanitized_pattern = pattern.replace("@rx ", "").strip()
        return sanitized_pattern if validate_regex(sanitized_pattern) else None

    return pattern if validate_regex(pattern) else None


def generate_nginx_waf(rules):
    categorized_rules = defaultdict(set)

    # Group rules by category without filtering any categories
    for rule in rules:
        category = rule.get("category", "generic").lower()
        pattern = rule.get("pattern")

        sanitized_pattern = sanitize_pattern(pattern)
        if sanitized_pattern:
            categorized_rules[category].add(sanitized_pattern)
        else:
            logging.warning(f"Invalid or unsupported pattern skipped: {pattern}")

    # Write Nginx configuration per category
    for category, patterns in categorized_rules.items():
        output_file = OUTPUT_DIR / f"{category}.conf"
        try:
            with open(output_file, "w") as f:
                f.write(f"# Nginx WAF rules for {category.upper()}\n")
                f.write("location / {\n")
                f.write("    set $attack_detected 0;\n\n")
                
                for pattern in patterns:
                    escaped_pattern = pattern.replace('"', '\\"')
                    f.write(f'    if ($request_uri ~* "{escaped_pattern}") {{\n')
                    f.write("        set $attack_detected 1;\n")
                    f.write("    }\n\n")

                f.write("    if ($attack_detected = 1) {\n")
                f.write("        return 403;\n")
                f.write("    }\n")
                f.write("}\n")

            logging.info(f"Generated {output_file} ({len(patterns)} patterns)")
        except IOError as e:
            logging.error(f"Failed to write {output_file}: {e}")


def main():
    try:
        logging.info("Loading OWASP rules...")
        owasp_rules = load_owasp_rules(INPUT_FILE)

        logging.info(f"Generating Nginx WAF configs from {len(owasp_rules)} rules...")
        generate_nginx_waf(owasp_rules)

        logging.info("Nginx WAF configurations generated successfully.")
    except Exception as e:
        logging.critical(f"Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
