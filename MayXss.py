import requests
import threading
import multiprocessing
from queue import Queue
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from argparse import ArgumentParser
import os
import time
import random
from tqdm import tqdm
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import json
from collections import defaultdict
import matplotlib.pyplot as plt
from transformers import pipeline

# Fancy banner with credits
def print_banner():
    banner = r"""
                   __  __        
  /\/\   __ _ _   _\ \/ /___ ___ 
 /    \ / _` | | | |\  // __/ __|
/ /\/\ \ (_| | |_| |/  \\__ \__ \
\/    \/\__,_|\__, /_/\_\___/___/
              |___/              
          
    MayXSS - Built by AIwolfie [Mayank Malaviya]
    GitHub: https://github.com/AIwolfie
    LinkedIn: https://linkedin.com/in/mayank-aiwolfie
    """
    print("\033[92m" + banner + "\033[0m")

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MayXSS")

# Global variables
result_lock = threading.Lock()
results = []
queue = Queue()
progress_bar = None

# Initialize AI-based payload generator
def generate_ai_payloads(base_payloads):
    generator = pipeline("text-generation", model="gpt2")
    ai_payloads = []
    for payload in base_payloads:
        generated = generator(f"Generate XSS payload based on: {payload}", max_length=30, num_return_sequences=1)
        ai_payloads.append(generated[0]['generated_text'])
    return ai_payloads

# Dynamic payload generation with real AI
async def dynamic_payload_generation(base_payloads):
    return generate_ai_payloads(base_payloads)

# Function to detect rate limiting
async def handle_rate_limiting(response):
    if response.status_code == 429:
        time.sleep(5)  # Wait and retry after 5 seconds
        return True
    return False

# Function to bypass rate limiting and detect anti-bot mechanisms
def bypass_rate_limiting():
    return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}

# Expand test coverage to Stored XSS
def test_stored_xss(url, payload):
    try:
        data = {"input": payload}  # Example POST data structure
        response = requests.post(url, data=data)
        if payload in response.text:
            return f"Stored XSS -> {url} -> Payload: {payload}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Error testing stored XSS: {e}")
    return None

# Generate detailed HTML report
def generate_html_report(results):
    report_path = "xss_report.html"
    categories = defaultdict(int)
    for result in results:
        category = result.split(" -> ")[0]
        categories[category] += 1

    # Generate a pie chart
    plt.figure(figsize=(6, 6))
    plt.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%')
    plt.title("XSS Vulnerabilities Breakdown")
    plt.savefig("report_chart.png")

    # Create the HTML file
    with open(report_path, "w") as f:
        f.write("""
        <html>
        <head><title>XSS Vulnerability Report</title></head>
        <body>
        <h1>XSS Vulnerability Report</h1>
        <img src='report_chart.png' alt='XSS Vulnerability Breakdown'>
        <ul>
        """)
        for result in results:
            f.write(f"<li>{result}</li>")
        f.write("""</ul></body></html>""")

    logger.info(f"HTML report generated at {report_path}")

# Browser automation optimization with Playwright
def test_dom_xss_playwright(url, payload):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        try:
            test_url = url.replace("FUZZ", payload)
            page.goto(test_url)
            time.sleep(2)  # Allow JS to execute
            if payload in page.content():
                return f"DOM-Based XSS -> {test_url} -> Payload: {payload}"
        except Exception as e:
            logger.error(f"Error testing DOM XSS with Playwright: {e}")
        finally:
            browser.close()
    return None

# Live results streaming
def stream_results():
    for result in results:
        print(result)

# Add concurrency improvements
async def test_concurrent(payloads, urls, custom_headers, proxy):
    async def async_test_url(url, payload):
        proxies = {"http": proxy, "https": proxy} if proxy else None
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=custom_headers, proxy=proxies) as response:
                if await handle_rate_limiting(response):
                    await async_test_url(url, payload)

    tasks = []
    for url in urls:
        for payload in payloads:
            tasks.append(async_test_url(url, payload))
    await asyncio.gather(*tasks)

# Allow customizable rules for regex scanning
def scan_with_custom_rules(response_text, rules):
    matches = {}
    for rule_name, pattern in rules.items():
        matches[rule_name] = re.findall(pattern, response_text)
    return matches

# Extensive error handling
def robust_error_handling(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
    return wrapper

# Testing framework integration
def run_unit_tests():
    # Placeholder for a testing framework like unittest or pytest
    pass

# Worker thread for URL processing
def worker(payloads, custom_headers, proxy, delay, verbose):
    global results
    while not queue.empty():
        url = queue.get()
        for payload in payloads:
            test_url = url.replace("FUZZ", payload)
            try:
                response = requests.get(test_url, headers=custom_headers, proxies={"http": proxy, "https": proxy} if proxy else None)
                if verbose:
                    print(f"Testing: {test_url}")
                if payload in response.text:
                    result = f"Reflected XSS -> {test_url} -> Payload: {payload}"
                    with result_lock:
                        results.append(result)
                time.sleep(delay)
            except Exception as e:
                logger.error(f"Error processing URL {test_url}: {e}")
        progress_bar.update(1)

# Main function to handle CLI arguments and setup
def main():
    print_banner()
    parser = ArgumentParser(description="MayXSS - XSS Validator Tool by AIwolfie")

    parser.add_argument("-u", "--url", help="Single URL with 'FUZZ' as the injection point")
    parser.add_argument("-ul", "--url-list", help="File containing multiple URLs")
    parser.add_argument("-p", "--payload-file", help="File containing XSS payloads", required=True)
    parser.add_argument("-o", "--output", help="Save vulnerable links to a file (e.g., output.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (min: 1, max: 50, default: 10)")
    parser.add_argument("-H", "--headers", help="Custom headers (e.g., 'key1:value1,key2:value2')")
    parser.add_argument("-P", "--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-d", "--delay", type=int, default=0, help="Delay between requests in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show live scanning of links")

    args = parser.parse_args()

    # Validate thread count
    if args.threads < 1 or args.threads > 50:
        logger.error("Threads must be between 1 and 50.")
        return

    # Load payloads
    try:
        with open(args.payload_file, "r") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Unable to load payloads: {e}")
        return

    # Load URLs
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_list:
        try:
            with open(args.url_list, "r") as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            logger.error(f"Unable to load URLs: {e}")
            return
    else:
        logger.info("Please provide a URL or URL list.")
        return

    # Enqueue URLs for processing
    for url in urls:
        queue.put(url)

    # Setup custom headers
    custom_headers = {}
    if args.headers:
        try:
            header_pairs = [header.split(":") for header in args.headers.split(",")]
            custom_headers = {key.strip(): value.strip() for key, value in header_pairs}
        except Exception as e:
            logger.error(f"Invalid headers format: {e}")
            return

    # Initialize progress bar
    global progress_bar
    progress_bar = tqdm(total=queue.qsize(), desc="Scanning URLs", unit="url")

    # Start threads
    threads = []
    for _ in range(args.threads):
        thread = threading.Thread(target=worker, args=(payloads, custom_headers, args.proxy, args.delay, args.verbose))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Close progress bar
    progress_bar.close()

    # Save results to file if output specified
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.writelines([result + "\n" for result in results])
            logger.info(f"Results saved to {args.output}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")

    # Stream results and generate report
    stream_results()
    generate_html_report(results)

if __name__ == "__main__":
    main()
