import requests
import os
import logging
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants and Configuration
OUTPUT_DIRS = {
    "nginx": "waf_patterns/nginx/",
    "caddy": "waf_patterns/caddy/",
    "apache": "waf_patterns/apache/",
    "traefik": "waf_patterns/traefik/",
    "haproxy": "waf_patterns/haproxy/"
}

BOT_LIST_SOURCES = [
    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
    "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json",
    "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
    "https://perishablepress.com/4g-ultimate-user-agent-blacklist/?format=txt"
    ]

RATE_LIMIT_DELAY = 600
RETRY_DELAY = 5
MAX_RETRIES = 3
EXPONENTIAL_BACKOFF = True
BACKOFF_MULTIPLIER = 2
MAX_WORKERS = 4
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def fetch_with_retries(url: str) -> list:
    retries = 0
    headers = {}

    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
        logging.info(f"Using GitHub token for {url}")

    while retries < MAX_RETRIES:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                logging.info(f"Fetched from {url}")
                return parse_bot_list(url, response)
            
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                reset_time = int(response.headers['X-RateLimit-Reset'])
                wait_time = max(reset_time - int(time.time()), RATE_LIMIT_DELAY)
                logging.warning(f"Rate limit exceeded for {url}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                jitter = random.uniform(1, 3)
                wait_time = (RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries) if EXPONENTIAL_BACKOFF else RETRY_DELAY) + jitter
                logging.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time:.2f} seconds.")
                time.sleep(wait_time)
                retries += 1
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            retries += 1

    logging.error(f"Failed to fetch {url} after {MAX_RETRIES} retries.")
    return []


def parse_bot_list(url: str, response: requests.Response) -> list:
    bot_patterns = set()
    try:
        if url.endswith(".json"):
            json_data = response.json()
            if isinstance(json_data, list):
                for entry in json_data:
                    bot_patterns.add(entry.get('pattern', entry.get('ua', '')))
            elif isinstance(json_data, dict):
                for entry in json_data.get('test_cases', []):
                    bot_patterns.add(entry.get('user_agent_string', ''))
        else:
            bot_patterns.update(response.text.splitlines())
    except (ValueError, json.JSONDecodeError) as e:
        logging.warning(f"Error parsing {url}: {e}")

    return list(bot_patterns)


def fetch_bot_list():
    bot_patterns = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_with_retries, url): url for url in BOT_LIST_SOURCES}

        for future in as_completed(future_to_url):
            result = future.result()
            bot_patterns.update(result)

    if not bot_patterns:
        logging.error("❌ No bots were fetched from any source. Exiting...")
        exit(1)

    logging.info(f"✅ Total unique bots collected: {len(bot_patterns)}")
    return sorted(bot_patterns)


def write_to_file(path: Path, content: str):
    try:
        with path.open("w") as f:
            f.write(content)
        logging.info(f"Generated file: {path}")
    except IOError as e:
        logging.error(f"Failed to write to {path}: {e}")


def generate_nginx_conf(bots):
    path = Path(OUTPUT_DIRS['nginx'], "bots.conf")
    content = "map $http_user_agent $bad_bot {\n"
    for bot in bots:
        content += f'    "~*{bot}" 1;\n'
    content += "    default 0;\n}\n"
    write_to_file(path, content)


def generate_caddy_conf(bots):
    path = Path(OUTPUT_DIRS['caddy'], "bots.conf")
    content = "@bad_bot {\n"
    for bot in bots:
        content += f'    header User-Agent *{bot}*\n'
    content += "}\nrespond @bad_bot 403\n"
    write_to_file(path, content)


def generate_apache_conf(bots):
    path = Path(OUTPUT_DIRS['apache'], "bots.conf")
    content = "SecRuleEngine On\n"
    for bot in bots:
        content += f'SecRule REQUEST_HEADERS:User-Agent "@contains {bot}" "id:3000,phase:1,deny,status:403"\n'
    write_to_file(path, content)


def generate_traefik_conf(bots):
    path = Path(OUTPUT_DIRS['traefik'], "bots.toml")
    content = "[http.middlewares]\n[http.middlewares.bad_bot_block]\n  [http.middlewares.bad_bot_block.plugin.badbot]\n    userAgent = [\n"
    for bot in bots:
        content += f'      "{bot}",\n'
    content += "    ]\n"
    write_to_file(path, content)


def generate_haproxy_conf(bots):
    path = Path(OUTPUT_DIRS['haproxy'], "bots.acl")
    content = "# HAProxy WAF - Bad Bot Blocker\n"
    for bot in bots:
        content += f'acl bad_bot hdr_sub(User-Agent) -i {bot}\n'
    content += "http-request deny if bad_bot\n"
    write_to_file(path, content)


if __name__ == "__main__":
    for output_dir in OUTPUT_DIRS.values():
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    bots = fetch_bot_list()

    generate_nginx_conf(bots)
    generate_caddy_conf(bots)
    generate_apache_conf(bots)
    generate_traefik_conf(bots)
    generate_haproxy_conf(bots)

    logging.info("[✔] Bot blocking configurations generated for all platforms.")
