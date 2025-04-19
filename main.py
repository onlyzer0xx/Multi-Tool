import os
import socket
import requests
import base64
import random
import string
import subprocess
import hashlib
import dns.resolver
from colorama import Fore, Style, init
from urllib.parse import urlparse
from bs4 import BeautifulSoup

init(autoreset=True)

BANNER = f"""{Fore.RED}
 ███████╗███████╗██████╗  ██████╗ 
 ╚══███╔╝██╔════╝██╔══██╗██╔═████╗
   ███╔╝ █████╗  ██████╔╝██║██╔██║
  ███╔╝  ██╔══╝  ██╔══██╗████╔╝██║
 ███████╗███████╗██║  ██║╚██████╔╝
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
"""

def clear():
    os.system('clear' if os.name != 'nt' else 'cls')

def pause():
    input(f"\n{Fore.CYAN}Press Enter to return to the main menu...{Style.RESET_ALL}")
    clear()
    print(BANNER)

def ip_lookup():
    ip = input("Enter IP address: ")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        for k, v in res.items():
            print(f"{k.capitalize()}: {v}")
    except:
        print("[!] Failed to get IP info.")
    pause()

def ping():
    host = input("Enter host: ")
    os.system(f"ping -c 4 {host}")
    pause()

def traceroute():
    host = input("Enter host: ")
    os.system(f"traceroute {host}")
    pause()

def port_scan():
    host = input("Enter host: ")
    print(f"Scanning ports on {host}...")
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is open")
        sock.close()
    pause()

def generate_password():
    length = int(input("Enter password length: "))
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print("Generated Password:", password)
    pause()

def encode_base64():
    text = input("Enter text to encode: ")
    encoded = base64.b64encode(text.encode()).decode()
    print("Encoded:", encoded)
    pause()

def decode_base64():
    text = input("Enter base64 to decode: ")
    try:
        decoded = base64.b64decode(text).decode()
        print("Decoded:", decoded)
    except:
        print("[!] Failed to decode.")
    pause()

def sha256_hash():
    text = input("Enter text to hash (SHA256): ")
    hash_obj = hashlib.sha256(text.encode())
    print("SHA256 Hash:", hash_obj.hexdigest())
    pause()

def dns_lookup():
    domain = input("Enter domain: ")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print(f"IP: {ipval.to_text()}")
    except:
        print("[!] Failed to resolve domain.")
    pause()

def check_proxy():
    try:
        ip_info = requests.get('http://ip-api.com/json/').json()
        for k, v in ip_info.items():
            print(f"{k.capitalize()}: {v}")
    except:
        print("[!] Failed to check proxy status.")
    pause()

def whois_lookup():
    domain = input("Enter domain: ")
    os.system(f"whois {domain}")
    pause()

def http_headers():
    url = input("Enter URL: ")
    try:
        response = requests.get(url)
        for k, v in response.headers.items():
            print(f"{k}: {v}")
    except:
        print("[!] Failed to retrieve headers.")
    pause()

def url_parser():
    url = input("Enter URL: ")
    parsed = urlparse(url)
    print(f"Scheme: {parsed.scheme}\nNetloc: {parsed.netloc}\nPath: {parsed.path}\nQuery: {parsed.query}")
    pause()

def extract_links_from_html():
    url = input("Enter webpage URL: ")
    try:
        html = requests.get(url).text
        soup = BeautifulSoup(html, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href:
                print(href)
    except:
        print("[!] Failed to extract links.")
    pause()

def nmap_scan():
    target = input("Enter target IP/domain: ")
    os.system(f"nmap -sV {target}")
    pause()

def check_sql_vuln():
    url = input("Enter URL to test (with parameter): ")
    payload = "'"
    try:
        r = requests.get(url + payload)
        if "sql" in r.text.lower() or "mysql" in r.text.lower():
            print("Possible SQL Injection vulnerability!")
        else:
            print("No obvious SQL Injection signs.")
    except:
        print("[!] Request failed.")
    pause()

def robots_txt():
    domain = input("Enter domain: ")
    try:
        r = requests.get(f"http://{domain}/robots.txt")
        print(r.text)
    except:
        print("[!] Couldn't fetch robots.txt")
    pause()

def email_scraper():
    url = input("Enter URL to scan for emails: ")
    try:
        page = requests.get(url).text
        emails = set(part for part in page.split() if "@" in part and "." in part)
        for email in emails:
            print(email)
    except:
        print("[!] Failed to fetch page or find emails.")
    pause()

def menu():
    clear()
    print(BANNER)
    while True:
        print(f"""
{Fore.BLUE}1. IP Lookup
{Fore.GREEN}2. Ping Host
{Fore.YELLOW}3. Traceroute
{Fore.CYAN}4. Port Scanner
{Fore.MAGENTA}5. Generate Password
{Fore.RED}6. Encode Base64
{Fore.WHITE}7. Decode Base64
{Fore.LIGHTGREEN_EX}8. SHA256 Hash
{Fore.LIGHTBLUE_EX}9. DNS Lookup
{Fore.LIGHTRED_EX}10. Proxy/VPN Check
{Fore.LIGHTYELLOW_EX}11. WHOIS Lookup
{Fore.LIGHTMAGENTA_EX}12. Get HTTP Headers
{Fore.LIGHTCYAN_EX}13. Parse URL
{Fore.LIGHTWHITE_EX}14. Extract Links from Webpage
{Fore.GREEN}15. Nmap Version Scan
{Fore.YELLOW}16. Basic SQLi Test
{Fore.CYAN}17. Read robots.txt
{Fore.MAGENTA}18. Email Scraper
{Fore.RED}0. Exit
""")
        choice = input("Select an option: ")
        if choice == '1': ip_lookup()
        elif choice == '2': ping()
        elif choice == '3': traceroute()
        elif choice == '4': port_scan()
        elif choice == '5': generate_password()
        elif choice == '6': encode_base64()
        elif choice == '7': decode_base64()
        elif choice == '8': sha256_hash()
        elif choice == '9': dns_lookup()
        elif choice == '10': check_proxy()
        elif choice == '11': whois_lookup()
        elif choice == '12': http_headers()
        elif choice == '13': url_parser()
        elif choice == '14': extract_links_from_html()
        elif choice == '15': nmap_scan()
        elif choice == '16': check_sql_vuln()
        elif choice == '17': robots_txt()
        elif choice == '18': email_scraper()
        elif choice == '0':
            print(f"\n{Fore.GREEN}Thanks for using zer0cyber{Style.RESET_ALL}")
            break
        else:
            print("Invalid choice.")
            pause()

if __name__ == '__main__':
    menu()
