import os
import re
import time
import json
import base64
import hashlib
import logging
import argparse
from typing import List, Dict, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
GITHUB_REPO_URL = "https://api.github.com/repos/coreruleset/coreruleset"
OWASP_CRS_BASE_URL = f"{GITHUB_REPO_URL}/contents/rules"
GITHUB_REF = "v4"  # Default version prefix
RATE_LIMIT_DELAY = 600  # Rate limit delay in seconds
RETRY_DELAY = 5  # Base retry delay in seconds
MAX_RETRIES = 6  # Maximum number of retries
EXPONENTIAL_BACKOFF = True  # Use exponential backoff for retries
BACKOFF_MULTIPLIER = 2  # Multiplier for exponential backoff
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # GitHub token for authentication
CONNECTION_POOL_SIZE = 20  # Increased connection pool size


class GitHubRequestError(Exception):
    """Raised when fetching data from GitHub fails after all retries."""


class GitHubRateLimitError(GitHubRequestError):
    """Raised when GitHub API rate limit is exceeded."""


class GitHubBlobFetchError(GitHubRequestError):
    """Raised when fetching a blob from GitHub fails."""


def get_session() -> requests.Session:
    """
    Creates and returns a requests.Session with optional GitHub token authentication.
    """
    session = requests.Session()
    if GITHUB_TOKEN:
        session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    # Increase connection pool size
    adapter = requests.adapters.HTTPAdapter(pool_connections=CONNECTION_POOL_SIZE, pool_maxsize=CONNECTION_POOL_SIZE)
    session.mount("https://", adapter)
    return session


def fetch_with_retries(session: requests.Session, url: str) -> requests.Response:
    """
    Fetches the given URL with retries, handling rate limits and transient HTTP errors.
    Raises GitHubRequestError if the request cannot be completed after all retries.
    """
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = session.get(url)
            if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers:
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                wait_time = max(reset_time - int(time.time()), RATE_LIMIT_DELAY)
                logger.warning(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            response.raise_for_status()
            return response
        except requests.HTTPError as e:
            logger.warning(f"HTTP error fetching {url}: {e}")
            wait_time = (RETRY_DELAY * (BACKOFF_MULTIPLIER ** retries)
                         if EXPONENTIAL_BACKOFF else RETRY_DELAY)
            logger.warning(f"Retrying {url}... ({retries + 1}/{MAX_RETRIES}) in {wait_time} seconds.")
            time.sleep(wait_time)
            retries += 1
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            retries += 1

    raise GitHubRequestError(f"Failed to fetch {url} after {MAX_RETRIES} retries.")


def fetch_latest_tag(session: requests.Session, ref_prefix: str) -> Optional[str]:
    """
    Fetches the latest matching Git tag from the GitHub repository based on a version prefix.
    Falls back to the newest tag if no matching prefix is found. Returns the tag reference.
    """
    ref_url = f"{GITHUB_REPO_URL}/git/refs/tags"
    try:
        response = fetch_with_retries(session, ref_url)
        tags = response.json()
        if not tags:
            logger.warning("No tags found in the repository.")
            return None
        matching = [r["ref"] for r in tags if r["ref"].startswith(f"refs/tags/{ref_prefix}.")]
        matching.sort(reverse=True, key=lambda x: x.split(".")[-1])
        if matching:
            latest_tag = matching[0]
            logger.info(f"Latest matching tag: {latest_tag}")
            return latest_tag
        logger.warning(f"No matching refs found for prefix {ref_prefix}. Falling back to the latest tag.")
        return tags[-1]["ref"]
    except Exception as e:
        logger.error(f"Failed to fetch tags. Reason: {e}")
        return None


def fetch_rule_files(session: requests.Session, ref: str) -> List[Dict[str, str]]:
    """
    Fetches the list of rule files (.conf) from the given ref in the repository.
    Returns a list of dictionaries containing file name and SHA.
    """
    ref_name = ref.split("/")[-1] if "/" in ref else ref
    rules_url = f"{OWASP_CRS_BASE_URL}?ref={ref_name}"
    try:
        response = fetch_with_retries(session, rules_url)
        files = response.json()
        return [{"name": f["name"], "sha": f["sha"]} for f in files if f["name"].endswith(".conf")]
    except (GitHubRequestError, requests.RequestException) as e:
        logger.error(f"Failed to fetch rule files from {rules_url}. Reason: {e}")
        return []


def fetch_github_blob(session: requests.Session, sha: str) -> str:
    """
    Fetches the blob content (base64-encoded) for a given SHA from GitHub.
    Returns the content if successful, or an empty string on failure.
    """
    blob_url = f"{GITHUB_REPO_URL}/git/blobs/{sha}"
    try:
        response = fetch_with_retries(session, blob_url)
        return response.json().get("content", "")
    except (GitHubRequestError, requests.RequestException) as e:
        logger.error(f"Failed to fetch blob for SHA {sha}. Reason: {e}")
        return ""


def verify_blob_sha(file_sha: str, blob_content_b64: str) -> bool:
    """
    Verifies that the SHA of the decoded content matches the expected file_sha.
    Logs a warning if the verification fails but does not block execution.
    """
    decoded_bytes = base64.b64decode(blob_content_b64)
    blob_header = f"blob {len(decoded_bytes)}\0".encode("utf-8")
    calculated_sha = hashlib.sha1(blob_header + decoded_bytes).hexdigest()

    if calculated_sha != file_sha:
        logger.warning(f"SHA mismatch for file. Expected: {file_sha}, Calculated: {calculated_sha}")
        return False
    return True


def extract_sec_rules(raw_text: str) -> List[str]:
    """
    Extracts SecRule patterns from the raw text.
    """
    return re.findall(r'SecRule\s+.*?"((?:[^"\\]|\\.)+?)"', raw_text, re.DOTALL)


def process_rule_file(file: Dict[str, str], session: requests.Session) -> List[Dict[str, str]]:
    """
    Processes a single rule file, fetching its content and extracting SecRule patterns.
    """
    rules = []
    blob_b64 = fetch_github_blob(session, file["sha"])
    if not blob_b64:
        logger.warning(f"Skipping file {file['name']} due to empty blob content.")
        return rules

    # Verify SHA (non-blocking)
    verify_blob_sha(file["sha"], blob_b64)

    raw_text = base64.b64decode(blob_b64).decode("utf-8")
    sec_rules = extract_sec_rules(raw_text)
    category = file["name"].split("-")[-1].replace(".conf", "")
    for rule in sec_rules:
        pattern = rule.strip().replace("\\", "")
        if pattern:
            rules.append({"category": category, "pattern": pattern})

    return rules


def fetch_owasp_rules(session: requests.Session, rule_files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Fetches the OWASP rule content for each rule file, extracts SecRule patterns,
    and returns a list of dicts with category and pattern.
    """
    rules = []
    with ThreadPoolExecutor(max_workers=CONNECTION_POOL_SIZE) as executor:
        futures = {
            executor.submit(process_rule_file, file, session): file for file in rule_files
        }
        for future in tqdm(as_completed(futures), total=len(rule_files), desc="Fetching rule files"):
            try:
                rules.extend(future.result())
            except Exception as e:
                logger.error(f"Failed to process file. Reason: {e}")

    logger.info(f"Fetched {len(rules)} rules.")
    return rules


def save_as_json(rules: List[Dict[str, str]], output_file: str) -> bool:
    """
    Saves the given list of rules to a JSON file. Returns True if successful, False otherwise.
    """
    try:
        output_dir = Path(output_file).parent
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
        # Atomic write using a temporary file
        temp_file = f"{output_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=4)
        # Rename temp file to the final output file
        os.replace(temp_file, output_file)
        logger.info(f"Rules saved to {output_file}.")
        return True
    except IOError as e:
        logger.error(f"Failed to save rules to {output_file}. Reason: {e}")
        return False


def main():
    """Main function to fetch and save OWASP rules."""
    parser = argparse.ArgumentParser(description="Fetch OWASP Core Rule Set rules from GitHub.")
    parser.add_argument("--output", type=str, default="owasp_rules.json", help="Output JSON file path.")
    parser.add_argument("--ref", type=str, default=GITHUB_REF, help="Git reference (e.g., tag or branch).")
    parser.add_argument("--dry-run", action="store_true", help="Simulate fetching without saving.")
    args = parser.parse_args()

    session = get_session()
    latest_ref = fetch_latest_tag(session, args.ref)
    if latest_ref:
        rule_files = fetch_rule_files(session, latest_ref)
        if rule_files:
            rules = fetch_owasp_rules(session, rule_files)
            if args.dry_run:
                logger.info("Dry-run mode enabled. Skipping file save.")
            elif rules and save_as_json(rules, args.output):
                logger.info("All rules fetched and saved successfully.")
            else:
                logger.error("Failed to fetch or save rules.")
        else:
            logger.error("Failed to fetch rule files.")
    else:
        logger.error("Failed to fetch tags.")


if __name__ == "__main__":
    main()