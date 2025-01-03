import os
import json

OUTPUT_DIR = "waf_patterns/traefik/"

def load_owasp_rules(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
        exit(1)
    except json.JSONDecodeError:
        print(f"[-] Error: Invalid JSON in '{file_path}'.")
        exit(1)

def generate_traefik_conf(rules):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    config_file = os.path.join(OUTPUT_DIR, "middleware.toml")

    try:
        with open(config_file, "w") as f:
            f.write("[http.middlewares]\n\n")
            rule_counter = 1  # Unique identifier for each middleware

            # Group rules by category
            grouped_rules = {}
            for rule in rules:
                category = rule.get("category", "default")
                if category not in grouped_rules:
                    grouped_rules[category] = []
                grouped_rules[category].append(rule)

            # Write grouped rules to the TOML file
            for category, rules_in_category in grouped_rules.items():
                f.write(f"[http.middlewares.bad_bot_block_{category}]\n")
                f.write(f"  [http.middlewares.bad_bot_block_{category}.plugin.badbot]\n")
                f.write("    userAgent = [\n")
                unique_rules = set()  # Use a set to deduplicate rules
                for rule in rules_in_category:
                    # Escape special characters in the pattern
                    pattern = rule['pattern'].replace('"', '\\"').replace("\\", "\\\\")
                    unique_rules.add(f'      "{pattern}"')
                f.write(",\n".join(unique_rules) + "\n")
                f.write("    ]\n\n")

        print(f"[+] Traefik WAF rules generated at {config_file}")
    except IOError as e:
        print(f"[-] Error writing to file: {e}")
        exit(1)

if __name__ == "__main__":
    owasp_rules = load_owasp_rules("owasp_rules.json")
    generate_traefik_conf(owasp_rules)
