#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, re, sys, time, os, socket
from multiprocessing.dummy import Pool
from colorama import Fore, Style, init
from datetime import datetime
from urllib.parse import urlparse
from requests.exceptions import RequestException

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

PRIMARY = Fore.CYAN + Style.BRIGHT
ACCENT = Fore.MAGENTA + Style.BRIGHT
GOOD = Fore.GREEN + Style.BRIGHT
WARN = Fore.YELLOW + Style.BRIGHT
BAD = Fore.RED + Style.BRIGHT
DIM = Style.DIM + Fore.WHITE
RESET = Style.RESET_ALL

DEFAULT_OUTPUT_FILE = "domain.txt"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 5

CONFIG = {
    "output_file": DEFAULT_OUTPUT_FILE,
    "enrich": False,
    "threads": DEFAULT_THREADS,
    "probe_timeout": DEFAULT_TIMEOUT,
}

PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SiteScraper/2.0; PentestMode)"
}


def truncate(text: str, limit: int = 120) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].strip() + "..."


def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return "N/A"


def extract_title(html: str) -> str:
    if not html:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return truncate(title)


def normalize_entry(raw: str):
    candidate = (raw or "").strip()
    if not candidate:
        return None
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip()
    if not host:
        return None
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or host
    sanitized_url = f"{scheme}://{netloc}"
    return {
        "raw": raw,
        "host": netloc.lower(),
        "url": sanitized_url,
    }


def prepare_domains(domains: list) -> list:
    seen = set()
    prepared = []
    for raw in domains:
        entry = normalize_entry(raw)
        if not entry:
            continue
        if entry["host"] in seen:
            continue
        seen.add(entry["host"])
        prepared.append(entry)
    return prepared


def probe_domain(entry: dict) -> dict:
    timeout = CONFIG.get("probe_timeout", DEFAULT_TIMEOUT)
    base_url = entry["url"]
    attempts = [base_url]
    if base_url.startswith("http://"):
        attempts.append(base_url.replace("http://", "https://", 1))
    elif base_url.startswith("https://"):
        attempts.append(base_url.replace("https://", "http://", 1))

    result = {
        "host": entry["host"],
        "base_url": base_url,
        "final_url": base_url,
        "status": "unreachable",
        "server": "unknown",
        "title": "",
        "ip": resolve_ip(entry["host"]),
        "success": False,
        "error": "",
    }

    for attempt in attempts:
        try:
            response = requests.get(
                attempt,
                headers=PROBE_HEADERS,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            result.update({
                "final_url": response.url,
                "status": response.status_code,
                "server": response.headers.get("Server", "unknown"),
                "title": extract_title(response.text),
                "ip": resolve_ip(urlparse(response.url).hostname or entry["host"]),
                "success": True,
                "error": "",
            })
            return result
        except RequestException as exc:
            result["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
    return result


def enrich_domains(entries: list) -> list:
    pool = Pool(CONFIG.get("threads", DEFAULT_THREADS))
    try:
        return pool.map(probe_domain, entries)
    finally:
        pool.close()
        pool.join()


def configure_run():
    output_choice = cinput(f"Output file path [{CONFIG['output_file']}]: ").strip()
    if output_choice:
        CONFIG["output_file"] = output_choice

    recon_choice = cinput("Enable HTTP probing to enrich results? (y/N): ").strip().lower()
    CONFIG["enrich"] = recon_choice.startswith("y")

    if CONFIG["enrich"]:
        threads_choice = cinput(f"Threads for probing [{CONFIG['threads']}]: ").strip()
        if threads_choice.isdigit() and int(threads_choice) > 0:
            CONFIG["threads"] = int(threads_choice)

        timeout_choice = cinput(f"Timeout (seconds) for probing [{CONFIG['probe_timeout']}]: ").strip()
        if timeout_choice:
            try:
                parsed_timeout = int(float(timeout_choice))
                if parsed_timeout > 0:
                    CONFIG["probe_timeout"] = parsed_timeout
            except ValueError:
                print(WARN + "[!] Invalid timeout provided. Using previous value." + RESET)


def cinput(prompt: str, color: str = PRIMARY) -> str:
    """Colorized input prompt."""
    return input(color + prompt + RESET)

def show_banner():
    clear_screen()
    print(ACCENT + r"""
===========================================
 SITE SCRAPER By roxm337
===========================================
""" + RESET)

    print(PRIMARY + "Scrape Directly:" + RESET)
    print(GOOD + "  [1] " + Fore.WHITE + "topmillion.net" + RESET)
    print()

    print(PRIMARY + "Scrape By TLD:" + RESET)
    print(GOOD + "  [2] " + Fore.WHITE + "azstats.org" + RESET)
    print(GOOD + "  [3] " + Fore.WHITE + "dubdomain.com" + RESET)
    print(GOOD + "  [4] " + Fore.WHITE + "greensiteinfo.com" + RESET)
    print()

    print(PRIMARY + "Scrape By Date:" + RESET)
    print(GOOD + "  [5] " + Fore.WHITE + "uidomains.com" + RESET)
    print(GOOD + "  [6] " + Fore.WHITE + "websitebiography.com" + RESET)
    print(ACCENT + "==========================================" + RESET)


def _ensure_output_path(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)


def _serialize_enriched(result: dict, source: str, timestamp: str) -> str:
    fields = [
        timestamp,
        source,
        result.get("host", ""),
        result.get("base_url", ""),
        result.get("final_url", ""),
        result.get("status", ""),
        result.get("ip", ""),
        result.get("server", ""),
        result.get("title", ""),
        result.get("error", ""),
    ]
    return "\t".join(str(field or "") for field in fields)


def save_domains(source: str, domains: list, option_number: int):
    """Persist domains with optional HTTP enrichment for pentest recon."""
    prepared = prepare_domains(domains)
    if not prepared:
        print(WARN + f"[!] No domains scraped from {source}." + RESET)
        return

    output_path = CONFIG.get("output_file", DEFAULT_OUTPUT_FILE)
    _ensure_output_path(output_path)

    if CONFIG.get("enrich"):
        timestamp = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        print(ACCENT + f"[+] Enriching {len(prepared)} domains (threads={CONFIG['threads']}, timeout={CONFIG['probe_timeout']}s)" + RESET)
        enriched = enrich_domains(prepared)
        header = "\t".join([
            "timestamp",
            "source",
            "host",
            "base_url",
            "final_url",
            "status",
            "ip",
            "server",
            "title",
            "error",
        ])
        need_header = not os.path.exists(output_path) or os.path.getsize(output_path) == 0
        lines = []
        for result in enriched:
            success = result.get("success", False)
            status = result.get("status", "unreachable")
            server = truncate(result.get("server", "unknown"), 60)
            title = truncate(result.get("title", ""), 80)
            ip_addr = result.get("ip", "N/A")
            error = truncate(result.get("error", ""), 80)
            line = _serialize_enriched(result, source, timestamp)
            lines.append(line)

            if success:
                status_text = f"{status}"
                color = GOOD
            else:
                status_text = f"{status} ({error or 'no response'})"
                color = WARN
            print(
                color
                + f"[{option_number}] {result.get('host', 'unknown')} -> {status_text} | IP: {ip_addr} | Server: {server} | Title: {title}"
                + RESET
            )

        with open(output_path, "a", encoding="utf-8") as file:
            if need_header:
                file.write(header + "\n")
            for line in lines:
                file.write(line + "\n")

        print(ACCENT + f"[+] Saved {len(lines)} enriched records to {output_path}\n" + RESET)
    else:
        output_lines = []
        for entry in prepared:
            host = entry["host"]
            output_lines.append(host)
            print(GOOD + f"[{option_number}] {host}" + RESET)

        with open(output_path, "a", encoding="utf-8") as file:
            for line in output_lines:
                file.write(line + "\n")

        print(ACCENT + f"[+] Saved {len(output_lines)} domains to {output_path}\n" + RESET)

def scrape_azstats():
    tld = cinput("Enter Top-Level Domain (e.g., com, org): ").strip()
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    for page in range(1, 5):
        url = f"https://azstats.org/top/domain-zone/{tld}/{page}"
        try:
            html = requests.get(url, headers=headers, timeout=10).text
            hits = re.findall(r'style="margin-left: 0;">(.*?)</a>', html)
            results.extend(hits)
        except Exception as e:
            print(BAD + f"[!] Error fetching {url}: {e}" + RESET)
            continue
    save_domains("azstats.org", results, 2)


def scrape_topmillion():
    start_page = int(cinput("Enter starting page number: "))
    end_page = int(cinput("Enter ending page number: "))
    threads = int(cinput("Enter number of threads (e.g., 10): "))
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    def fetch_page(page):
        url = f"https://www.topmillion.net/pages/websites/page/{page}/"
        try:
            html = requests.get(url, headers=headers, timeout=10).text
            matches = re.findall(r'https://(.*?)\?w=400" alt=', html)
            return [f"http://{m}" for m in matches]
        except Exception as e:
            print(BAD + f"[!] Error fetching {url}: {e}" + RESET)
            return []

    pool = Pool(threads)
    pages_data = pool.map(fetch_page, range(start_page, end_page + 1))
    pool.close(); pool.join()

    for batch in pages_data:
        results.extend(batch)

    save_domains("topmillion.net", results, 1)


def scrape_dubdomain():
    start_page = int(cinput("Enter starting page number: "))
    end_page = int(cinput("Enter ending page number: "))
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    for page in range(start_page, end_page + 1):
        url = f"https://www.dubdomain.com/index.php?page={page}"
        try:
            html = requests.get(url, headers=headers, timeout=10).text
            matches = re.findall(r'data-src="https://www.google.com/s2/favicons\?domain_url=(.*?)"', html)
            results.extend([f"http://{m}" for m in matches])
        except Exception as e:
            print(BAD + f"[!] Error fetching {url}: {e}" + RESET)
            continue
    save_domains("dubdomain.com", results, 3)


def scrape_uidomains():
    date_input = cinput("Enter date (format: YYYY-MM-DD): ").strip()
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    url = f"https://www.uidomains.com/browse-daily-domains-difference/0/{date_input}"
    try:
        html = requests.get(url, headers=headers, timeout=10).text
        matches = re.findall(r'<li>([a-zA-Z0-9\-.]+)</li>', html)
        results.extend([f"http://{m}" for m in matches])
    except Exception as e:
        print(BAD + f"[!] Error: {e}" + RESET)
    save_domains("uidomains.com", results, 5)


def scrape_greensiteinfo():
    tld = cinput("Enter Top-Level Domain (e.g., com, org): ").strip()
    start_page = int(cinput("Enter starting page number: "))
    end_page = int(cinput("Enter ending page number: "))
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    for page in range(start_page, end_page + 1):
        url = f"https://www.greensiteinfo.com/domains/.{tld}/{page}/"
        try:
            html = requests.get(url, headers=headers, timeout=10).text
            matches = re.findall(r'<a href = https://www.greensiteinfo.com/search/(.*?)/ >', html)
            results.extend([f"http://{m}" for m in matches])
        except Exception as e:
            print(BAD + f"[!] Error fetching {url}: {e}" + RESET)
            continue
    save_domains("greensiteinfo.com", results, 4)


def scrape_websitebiography():
    date_input = cinput("Enter date (format: YYYY-MM-DD): ").strip()
    start_page = int(cinput("Enter starting page number: "))
    end_page = int(cinput("Enter ending page number: "))
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []
    for page in range(start_page, end_page + 1):
        url = f"https://websitebiography.com/new_domain_registrations/{date_input}/{page}/"
        try:
            html = requests.get(url, headers=headers, timeout=10).text
            matches = re.findall(r"<a href='https://(.*?).websitebiography.com' title=", html)
            results.extend([f"http://{m}" for m in matches])
        except Exception as e:
            print(BAD + f"[!] Error fetching {url}: {e}" + RESET)
            continue
    save_domains("websitebiography.com", results, 6)

def main():
    show_banner()
    configure_run()
    choice = cinput("Please select an option number from the menu: ").strip()
    if choice == '1': scrape_topmillion()
    elif choice == '2': scrape_azstats()
    elif choice == '3': scrape_dubdomain()
    elif choice == '4': scrape_greensiteinfo()
    elif choice == '5': scrape_uidomains()
    elif choice == '6': scrape_websitebiography()
    else:
        print(BAD + "Invalid Option! Please try again." + RESET)


if __name__ == "__main__":
    main()
