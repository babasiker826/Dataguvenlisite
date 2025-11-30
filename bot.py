from flask import Flask, request, jsonify, make_response
import time
from collections import defaultdict
import hashlib
import uuid
import ipaddress
import threading

app = Flask(__name__)

# Güvenlik Konfigürasyonları
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10 # Daha düşük rate limit
RATE_LIMIT_BLOCK_DURATION = 7200  # 2 saat blok

# Gelişmiş IP bazlı rate limiting
request_log = defaultdict(list)
blocked_ips = {}
user_sessions = {}
ip_attempts = defaultdict(int)
suspicious_ips = set()

# Türkiye ve Azerbaycan IP aralıkları
TURKEY_IP_RANGES = [
    '78.160.0.0/14', '78.164.0.0/14', '78.168.0.0/14', '78.172.0.0/14',
    '78.176.0.0/13', '78.184.0.0/14', '78.188.0.0/14', '78.192.0.0/11',
    '81.212.0.0/14', '85.96.0.0/12', '85.104.0.0/14', '85.108.0.0/14',
    '85.112.0.0/13', '88.224.0.0/11', '89.19.0.0/19', '89.106.0.0/19',
    '89.145.0.0/19', '91.93.0.0/16', '94.54.0.0/15', '94.73.0.0/16',
    '94.78.0.0/18', '94.100.0.0/16', '94.102.0.0/17', '94.120.0.0/14',
    '95.0.0.0/12', '95.70.0.0/15', '95.130.0.0/17', '109.228.0.0/17',
    '109.232.0.0/21', '109.235.0.0/21', '109.238.0.0/20', '130.180.0.0/16',
    '134.255.0.0/16', '144.122.0.0/16', '159.146.0.0/16', '164.138.0.0/16',
    '176.33.0.0/16', '176.40.0.0/14', '176.52.0.0/17', '176.54.0.0/15',
    '176.56.0.0/14', '176.88.0.0/14', '176.92.0.0/15', '176.216.0.0/14',
    '176.220.0.0/16', '176.232.0.0/13', '176.240.0.0/16', '178.20.0.0/15',
    '178.40.0.0/15', '178.48.0.0/15', '178.60.0.0/14', '178.64.0.0/13',
    '178.72.0.0/13', '178.80.0.0/12', '178.96.0.0/11', '178.128.0.0/11',
    '178.160.0.0/12', '178.176.0.0/13', '178.184.0.0/14', '178.188.0.0/15',
    '178.190.0.0/16', '178.192.0.0/11', '178.224.0.0/13', '178.232.0.0/14',
    '178.236.0.0/17', '178.236.128.0/18', '178.237.0.0/16', '178.238.0.0/15',
    '178.240.0.0/13', '185.4.0.0/22', '185.8.0.0/22', '185.12.0.0/22',
    '185.16.0.0/22', '185.20.0.0/22', '185.24.0.0/22', '185.28.0.0/22',
    '185.32.0.0/22', '185.36.0.0/22', '185.40.0.0/22', '185.44.0.0/22',
    '185.48.0.0/22', '185.52.0.0/22', '185.56.0.0/22', '185.60.0.0/22',
    '185.64.0.0/22', '185.68.0.0/22', '185.72.0.0/22', '185.76.0.0/22',
    '185.80.0.0/22', '185.84.0.0/22', '185.88.0.0/22', '185.92.0.0/22',
    '185.96.0.0/22', '185.100.0.0/22', '185.104.0.0/22', '185.108.0.0/22',
    '185.112.0.0/22', '185.116.0.0/22', '185.120.0.0/22', '185.124.0.0/22',
    '185.128.0.0/22', '185.132.0.0/22', '185.136.0.0/22', '185.140.0.0/22',
    '185.144.0.0/22', '185.148.0.0/22', '185.152.0.0/22', '185.156.0.0/22',
    '185.160.0.0/22', '185.164.0.0/22', '185.168.0.0/22', '185.172.0.0/22',
    '185.176.0.0/22', '185.180.0.0/22', '185.184.0.0/22', '185.188.0.0/22',
    '185.192.0.0/22', '185.196.0.0/22', '185.200.0.0/22', '185.204.0.0/22',
    '185.208.0.0/22', '185.212.0.0/22', '185.216.0.0/22', '185.220.0.0/22',
    '185.224.0.0/22', '185.228.0.0/22', '185.232.0.0/22', '185.236.0.0/22',
    '185.240.0.0/22', '185.244.0.0/22', '185.248.0.0/22', '185.252.0.0/22',
    '188.3.0.0/16', '188.38.0.0/16', '188.41.0.0/16', '188.56.0.0/14',
    '188.119.0.0/18', '188.124.0.0/19', '188.132.0.0/14', '192.129.0.0/16',
    '193.140.0.0/16', '193.192.0.0/16', '193.255.0.0/16', '194.27.0.0/16',
    '194.54.0.0/16', '195.8.0.0/16', '195.39.0.0/16', '195.46.0.0/16',
    '195.85.0.0/16', '195.87.0.0/16', '195.155.0.0/16', '195.174.0.0/16',
    '195.175.0.0/16', '195.214.0.0/16', '195.234.0.0/16', '195.244.0.0/16',
    '212.2.0.0/19', '212.12.0.0/19', '212.15.0.0/19', '212.46.0.0/19',
    '212.58.0.0/19', '212.64.0.0/19', '212.68.0.0/19', '212.98.0.0/19',
    '212.101.0.0/19', '212.108.0.0/19', '212.112.0.0/19', '212.115.0.0/19',
    '212.126.0.0/19', '212.133.0.0/19', '212.156.0.0/16', '212.174.0.0/16',
    '212.175.0.0/16', '212.224.0.0/16', '213.14.0.0/16', '213.43.0.0/16',
    '213.74.0.0/16', '213.128.0.0/16', '213.153.0.0/16', '213.155.0.0/16',
    '213.186.0.0/16', '213.194.0.0/16', '213.232.0.0/16', '213.238.0.0/16'
]

# Azerbaycan IP aralıkları
AZERBAIJAN_IP_RANGES = [
    '5.0.0.0/16', '5.1.0.0/16', '5.2.0.0/16', '5.3.0.0/16',
    '5.4.0.0/16', '5.5.0.0/16', '5.6.0.0/16', '5.7.0.0/16',
    '5.8.0.0/16', '5.9.0.0/16', '5.10.0.0/16', '5.11.0.0/16',
    '5.12.0.0/16', '5.13.0.0/16', '5.14.0.0/16', '5.15.0.0/16',
    '31.0.0.0/16', '31.1.0.0/16', '31.2.0.0/16', '31.3.0.0/16',
    '31.4.0.0/16', '31.5.0.0/16', '31.6.0.0/16', '31.7.0.0/16',
    '31.8.0.0/16', '31.9.0.0/16', '31.10.0.0/16', '31.11.0.0/16',
    '31.12.0.0/16', '31.13.0.0/16', '31.14.0.0/16', '31.15.0.0/16',
    '31.16.0.0/16', '31.17.0.0/16', '31.18.0.0/16', '31.19.0.0/16',
    '31.20.0.0/16', '31.21.0.0/16', '31.22.0.0/16', '31.23.0.0/16',
    '31.24.0.0/16', '31.25.0.0/16', '31.26.0.0/16', '31.27.0.0/16',
    '31.28.0.0/16', '31.29.0.0/16', '31.30.0.0/16', '31.31.0.0/16',
    '37.0.0.0/16', '37.1.0.0/16', '37.2.0.0/16', '37.3.0.0/16',
    '37.4.0.0/16', '37.5.0.0/16', '37.6.0.0/16', '37.7.0.0/16',
    '37.8.0.0/16', '37.9.0.0/16', '37.10.0.0/16', '37.11.0.0/16',
    '37.12.0.0/16', '37.13.0.0/16', '37.14.0.0/16', '37.15.0.0/16',
    '37.16.0.0/16', '37.17.0.0/16', '37.18.0.0/16', '37.19.0.0/16',
    '37.20.0.0/16', '37.21.0.0/16', '37.22.0.0/16', '37.23.0.0/16',
    '37.24.0.0/16', '37.25.0.0/16', '37.26.0.0/16', '37.27.0.0/16',
    '37.28.0.0/16', '37.29.0.0/16', '37.30.0.0/16', '37.31.0.0/16',
    '46.0.0.0/16', '46.1.0.0/16', '46.2.0.0/16', '46.3.0.0/16',
    '46.4.0.0/16', '46.5.0.0/16', '46.6.0.0/16', '46.7.0.0/16',
    '46.8.0.0/16', '46.9.0.0/16', '46.10.0.0/16', '46.11.0.0/16',
    '46.12.0.0/16', '46.13.0.0/16', '46.14.0.0/16', '46.15.0.0/16',
    '77.0.0.0/16', '77.1.0.0/16', '77.2.0.0/16', '77.3.0.0/16',
    '77.4.0.0/16', '77.5.0.0/16', '77.6.0.0/16', '77.7.0.0/16',
    '77.8.0.0/16', '77.9.0.0/16', '77.10.0.0/16', '77.11.0.0/16',
    '77.12.0.0/16', '77.13.0.0/16', '77.14.0.0/16', '77.15.0.0/16',
    '77.16.0.0/16', '77.17.0.0/16', '77.18.0.0/16', '77.19.0.0/16',
    '77.20.0.0/16', '77.21.0.0/16', '77.22.0.0/16', '77.23.0.0/16',
    '77.24.0.0/16', '77.25.0.0/16', '77.26.0.0/16', '77.27.0.0/16',
    '77.28.0.0/16', '77.29.0.0/16', '77.30.0.0/16', '77.31.0.0/16',
    '78.0.0.0/16', '78.1.0.0/16', '78.2.0.0/16', '78.3.0.0/16',
    '78.4.0.0/16', '78.5.0.0/16', '78.6.0.0/16', '78.7.0.0/16',
    '78.8.0.0/16', '78.9.0.0/16', '78.10.0.0/16', '78.11.0.0/16',
    '78.12.0.0/16', '78.13.0.0/16', '78.14.0.0/16', '78.15.0.0/16',
    '78.16.0.0/16', '78.17.0.0/16', '78.18.0.0/16', '78.19.0.0/16',
    '78.20.0.0/16', '78.21.0.0/16', '78.22.0.0/16', '78.23.0.0/16',
    '78.24.0.0/16', '78.25.0.0/16', '78.26.0.0/16', '78.27.0.0/16',
    '78.28.0.0/16', '78.29.0.0/16', '78.30.0.0/16', '78.31.0.0/16',
    '79.0.0.0/16', '79.1.0.0/16', '79.2.0.0/16', '79.3.0.0/16',
    '79.4.0.0/16', '79.5.0.0/16', '79.6.0.0/16', '79.7.0.0/16',
    '79.8.0.0/16', '79.9.0.0/16', '79.10.0.0/16', '79.11.0.0/16',
    '79.12.0.0/16', '79.13.0.0/16', '79.14.0.0/16', '79.15.0.0/16',
    '79.16.0.0/16', '79.17.0.0/16', '79.18.0.0/16', '79.19.0.0/16',
    '79.20.0.0/16', '79.21.0.0/16', '79.22.0.0/16', '79.23.0.0/16',
    '79.24.0.0/16', '79.25.0.0/16', '79.26.0.0/16', '79.27.0.0/16',
    '79.28.0.0/16', '79.29.0.0/16', '79.30.0.0/16', '79.31.0.0/16',
    '85.0.0.0/16', '85.1.0.0/16', '85.2.0.0/16', '85.3.0.0/16',
    '85.4.0.0/16', '85.5.0.0/16', '85.6.0.0/16', '85.7.0.0/16',
    '85.8.0.0/16', '85.9.0.0/16', '85.10.0.0/16', '85.11.0.0/16',
    '85.12.0.0/16', '85.13.0.0/16', '85.14.0.0/16', '85.15.0.0/16',
    '85.16.0.0/16', '85.17.0.0/16', '85.18.0.0/16', '85.19.0.0/16',
    '85.20.0.0/16', '85.21.0.0/16', '85.22.0.0/16', '85.23.0.0/16',
    '85.24.0.0/16', '85.25.0.0/16', '85.26.0.0/16', '85.27.0.0/16',
    '85.28.0.0/16', '85.29.0.0/16', '85.30.0.0/16', '85.31.0.0/16',
    '94.0.0.0/16', '94.1.0.0/16', '94.2.0.0/16', '94.3.0.0/16',
    '94.4.0.0/16', '94.5.0.0/16', '94.6.0.0/16', '94.7.0.0/16',
    '94.8.0.0/16', '94.9.0.0/16', '94.10.0.0/16', '94.11.0.0/16',
    '94.12.0.0/16', '94.13.0.0/16', '94.14.0.0/16', '94.15.0.0/16',
    '94.16.0.0/16', '94.17.0.0/16', '94.18.0.0/16', '94.19.0.0/16',
    '94.20.0.0/16', '94.21.0.0/16', '94.22.0.0/16', '94.23.0.0/16',
    '94.24.0.0/16', '94.25.0.0/16', '94.26.0.0/16', '94.27.0.0/16',
    '94.28.0.0/16', '94.29.0.0/16', '94.30.0.0/16', '94.31.0.0/16',
    '95.0.0.0/16', '95.1.0.0/16', '95.2.0.0/16', '95.3.0.0/16',
    '95.4.0.0/16', '95.5.0.0/16', '95.6.0.0/16', '95.7.0.0/16',
    '95.8.0.0/16', '95.9.0.0/16', '95.10.0.0/16', '95.11.0.0/16',
    '95.12.0.0/16', '95.13.0.0/16', '95.14.0.0/16', '95.15.0.0/16',
    '95.16.0.0/16', '95.17.0.0/16', '95.18.0.0/16', '95.19.0.0/16',
    '95.20.0.0/16', '95.21.0.0/16', '95.22.0.0/16', '95.23.0.0/16',
    '95.24.0.0/16', '95.25.0.0/16', '95.26.0.0/16', '95.27.0.0/16',
    '95.28.0.0/16', '95.29.0.0/16', '95.30.0.0/16', '95.31.0.0/16',
    '176.0.0.0/16', '176.1.0.0/16', '176.2.0.0/16', '176.3.0.0/16',
    '176.4.0.0/16', '176.5.0.0/16', '176.6.0.0/16', '176.7.0.0/16',
    '176.8.0.0/16', '176.9.0.0/16', '176.10.0.0/16', '176.11.0.0/16',
    '176.12.0.0/16', '176.13.0.0/16', '176.14.0.0/16', '176.15.0.0/16',
    '176.16.0.0/16', '176.17.0.0/16', '176.18.0.0/16', '176.19.0.0/16',
    '176.20.0.0/16', '176.21.0.0/16', '176.22.0.0/16', '176.23.0.0/16',
    '176.24.0.0/16', '176.25.0.0/16', '176.26.0.0/16', '176.27.0.0/16',
    '176.28.0.0/16', '176.29.0.0/16', '176.30.0.0/16', '176.31.0.0/16',
    '178.0.0.0/16', '178.1.0.0/16', '178.2.0.0/16', '178.3.0.0/16',
    '178.4.0.0/16', '178.5.0.0/16', '178.6.0.0/16', '178.7.0.0/16',
    '178.8.0.0/16', '178.9.0.0/16', '178.10.0.0/16', '178.11.0.0/16',
    '178.12.0.0/16', '178.13.0.0/16', '178.14.0.0/16', '178.15.0.0/16',
    '178.16.0.0/16', '178.17.0.0/16', '178.18.0.0/16', '178.19.0.0/16',
    '178.20.0.0/16', '178.21.0.0/16', '178.22.0.0/16', '178.23.0.0/16',
    '178.24.0.0/16', '178.25.0.0/16', '178.26.0.0/16', '178.27.0.0/16',
    '178.28.0.0/16', '178.29.0.0/16', '178.30.0.0/16', '178.31.0.0/16',
    '188.0.0.0/16', '188.1.0.0/16', '188.2.0.0/16', '188.3.0.0/16',
    '188.4.0.0/16', '188.5.0.0/16', '188.6.0.0/16', '188.7.0.0/16',
    '188.8.0.0/16', '188.9.0.0/16', '188.10.0.0/16', '188.11.0.0/16',
    '188.12.0.0/16', '188.13.0.0/16', '188.14.0.0/16', '188.15.0.0/16',
    '188.16.0.0/16', '188.17.0.0/16', '188.18.0.0/16', '188.19.0.0/16',
    '188.20.0.0/16', '188.21.0.0/16', '188.22.0.0/16', '188.23.0.0/16',
    '188.24.0.0/16', '188.25.0.0/16', '188.26.0.0/16', '188.27.0.0/16',
    '188.28.0.0/16', '188.29.0.0/16', '188.30.0.0/16', '188.31.0.0/16',
    '213.0.0.0/16', '213.1.0.0/16', '213.2.0.0/16', '213.3.0.0/16',
    '213.4.0.0/16', '213.5.0.0/16', '213.6.0.0/16', '213.7.0.0/16',
    '213.8.0.0/16', '213.9.0.0/16', '213.10.0.0/16', '213.11.0.0/16',
    '213.12.0.0/16', '213.13.0.0/16', '213.14.0.0/16', '213.15.0.0/16'
]

# VPN/Proxy IP listeleri
VPN_IP_RANGES = [
    '185.159.131.', '45.137.21.', '193.29.13.', '91.199.117.',
    '45.95.147.', '185.220.101.', '185.165.190.', '45.142.214.',
    '5.188.', '5.189.', '5.190.', '5.191.',  # Ek VPN IP'leri
]

# Şüpheli User Agent'lar
SUSPICIOUS_USER_AGENTS = [
    'python', 'requests', 'curl', 'wget', 'scrapy', 'bot', 'crawler', 
    'spider', 'monitor', 'headless', 'phantom', 'selenium', 'automation',
    'nikto', 'sqlmap', 'nmap', 'metasploit'  # Ek güvenlik araçları
]

# Geçerli User Agent'lar
VALID_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
]

# DDoS koruma için thread lock
ddos_lock = threading.Lock()

def get_real_ip():
    """Gerçek client IP'sini al"""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    elif request.headers.get('X-Forwarded-For'):
        ips = request.headers.get('X-Forwarded-For', '').split(',')
        return ips[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def ip_to_int(ip):
    """IP adresini integer'a çevir"""
    try:
        return int(ipaddress.IPv4Address(ip))
    except:
        return None

def check_allowed_ip(ip):
    """IP'nin Türkiye veya Azerbaycan'dan olup olmadığını kontrol et"""
    try:
        ip_int = ip_to_int(ip)
        if ip_int is None:
            return False
            
        # Türkiye IP kontrolü
        for ip_range in TURKEY_IP_RANGES:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            if ip_int >= int(network[0]) and ip_int <= int(network[-1]):
                return True
        
        # Azerbaycan IP kontrolü
        for ip_range in AZERBAIJAN_IP_RANGES:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            if ip_int >= int(network[0]) and ip_int <= int(network[-1]):
                return True
                
        return False
    except Exception as e:
        print(f"IP kontrol hatası: {e}")
        return False

def check_vpn_proxy(ip):
    """VPN/Proxy kontrolü"""
    for vpn_range in VPN_IP_RANGES:
        if ip.startswith(vpn_range):
            return True
    return False

def check_suspicious_headers(headers):
    """Şüpheli header kontrolü"""
    suspicious_headers = [
        'X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP',
        'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr',
        'X-Client-IP', 'X-Host', 'X-Forwarded-Host'
    ]
    
    suspicious_count = 0
    for header in suspicious_headers:
        if header in headers:
            suspicious_count += 1
    
    return suspicious_count > 2

def check_user_agent(user_agent):
    """User Agent kontrolü"""
    if not user_agent:
        return False, "User Agent bulunamadı"
    
    user_agent_lower = user_agent.lower()
    
    for suspicious in SUSPICIOUS_USER_AGENTS:
        if suspicious in user_agent_lower:
            return False, f"Şüpheli User Agent: {suspicious}"
    
    is_valid = any(valid_ua in user_agent for valid_ua in VALID_USER_AGENTS)
    if not is_valid:
        return False, "Geçersiz User Agent"
    
    return True, "OK"

def advanced_rate_limit(ip, session_id):
    """Gelişmiş rate limiting kontrolü"""
    now = time.time()
    
    # IP blok kontrolü
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return False, "IP adresiniz 2 saat süreyle bloklanmıştır."
        else:
            del blocked_ips[ip]
    
    # Hızlı istek kontrolü (10 saniyede 10'dan fazla istek)
    rapid_window_start = now - 10
    rapid_requests = [timestamp for timestamp in request_log.get(session_id, []) if timestamp > rapid_window_start]
    
    if len(rapid_requests) > 10:
        blocked_ips[ip] = now + RATE_LIMIT_BLOCK_DURATION
        return False, "Çok hızlı istek gönderiyorsunuz. IP adresiniz 2 saat süreyle bloklanmıştır."
    
    # Normal rate limiting
    window_start = now - RATE_LIMIT_WINDOW
    request_log[session_id] = [timestamp for timestamp in request_log.get(session_id, []) if timestamp > window_start]
    
    if len(request_log[session_id]) >= RATE_LIMIT_MAX_REQUESTS:
        blocked_ips[ip] = now + RATE_LIMIT_BLOCK_DURATION
        return False, "Rate limit aşıldı. IP adresiniz 2 saat süreyle bloklanmıştır."
    
    request_log[session_id].append(now)
    return True, "OK"

def check_ddos_pattern(ip):
    """DDoS saldırı pattern'ini kontrol et"""
    now = time.time()
    
    with ddos_lock:
        ip_attempts[ip] += 1
        
        # 10 saniyede 20'den fazla istek = DDoS şüphesi
        if ip_attempts[ip] > 20:
            suspicious_ips.add(ip)
            blocked_ips[ip] = now + RATE_LIMIT_BLOCK_DURATION * 2  # 4 saat blok
            return False
        
        # Her dakika attempt sayısını sıfırla
        if now % 60 == 0:
            ip_attempts[ip] = 0
            
    return True

def create_user_session(request):
    """Kullanıcı session'ı oluşturma"""
    session_id = str(uuid.uuid4())
    fingerprint = generate_user_fingerprint(request)
    
    user_sessions[session_id] = {
        'fingerprint': fingerprint,
        'ip': get_real_ip(),
        'user_agent': request.headers.get('User-Agent'),
        'created_at': time.time(),
        'request_count': 0,
        'last_request': time.time()
    }
    
    return session_id

def validate_session(session_id, request):
    """Session doğrulama"""
    if session_id not in user_sessions:
        return False, "Geçersiz session"
    
    session = user_sessions[session_id]
    current_fingerprint = generate_user_fingerprint(request)
    
    if session['fingerprint'] != current_fingerprint:
        return False, "Session fingerprint uyuşmuyor"
    
    if time.time() - session['created_at'] > 3600:
        del user_sessions[session_id]
        return False, "Session süresi dolmuş"
    
    # Çok hızlı istek kontrolü
    current_time = time.time()
    if current_time - session['last_request'] < 0.5:  # 500ms'den hızlı istek
        return False, "Çok hızlı istek gönderiyorsunuz"
    
    session['last_request'] = current_time
    return True, "OK"

def generate_user_fingerprint(request):
    """Kullanıcı fingerprint oluşturma"""
    components = [
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.headers.get('Accept', ''),
        get_real_ip()
    ]
    fingerprint_string = '|'.join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

# 78 ADET DATA SETİ (Önceki gibi aynı)
DATA_SETS = {
    'all': [
        # Data setleri burada (önceki gibi 78 adet)
        # Kısaltma için örnek birkaç tane bırakıyorum
        {'name': '200m Gsm', 'size': '4.2 GB', 'desc': 'Türkiye\'nin en kapsamlı GSM veritabanı', 'update': '01.07.2024', 'url': 'https://drive.google.com/file/d/1oo6_RJcd9qWywx6l0yvol9cRXbOyQdow/view?usp=sharing', 'vip': True},
        {'name': '195m Gsm', 'size': '3.8 GB', 'desc': 'GSM numarası veritabanı', 'update': '28.05.2024', 'url': 'https://drive.google.com/file/d/16UUUBaqFqRD1guzNEk8hjvKZ3cHfZNUX/view?usp=sharing', 'vip': True},
        # ... diğer 76 veri seti
    ],
    # Diğer kategoriler...
}

# Kategorileri doldurma fonksiyonu (önceki gibi)

def generate_data_card(data):
    """Data kartı HTML oluşturma"""
    vip_badge = ''
    btn_class = 'download-btn'
    
    if data['vip']:
        vip_badge = '''
        <div class="vip-badge">
            <i class="fas fa-crown"></i> VIP
        </div>
        '''
        btn_class += ' premium'
    
    return f'''
    <div class="data-card">
        {vip_badge}
        <div class="data-card-header">
            <h3>{data['name']}</h3>
            <span class="data-size">{data['size']}</span>
        </div>
        <p class="data-description">{data['desc']}</p>
        <div class="data-meta">
            <div class="data-updated">
                <i class="far fa-calendar-alt"></i>
                <span>Güncelleme: {data['update']}</span>
            </div>
            <div class="data-format">
                <i class="far fa-file-alt"></i>
                <span>CSV/ZIP</span>
            </div>
        </div>
        <a href="{data['url']}" target="_blank" class="{btn_class}">
            <i class="fas fa-download"></i> Nabi System {'VIP' if data['vip'] else ''} İndir
        </a>
    </div>
    '''

def generate_data_section(category):
    """Data bölümü HTML oluşturma"""
    data_cards = ''
    for data in DATA_SETS.get(category, []):
        data_cards += generate_data_card(data)
    
    return f'''
    <div class="data-grid">
        {data_cards}
    </div>
    '''

# HTML TEMPLATE (Güncellenmiş)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nabi System - Premium Data Web</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* CSS aynı kalacak, sadece ek badge'ler eklendi */
        .azerbaijan-badge {
            position: fixed;
            top: 20px;
            left: 180px;
            background: linear-gradient(135deg, #00A651, #0099CC);
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        .ddos-protection {
            position: fixed;
            top: 60px;
            right: 20px;
            background: linear-gradient(135deg, #FF6B35, #FF2E2E);
            color: white;
            padding: 8px 12px;
            border-radius: 15px;
            font-size: 0.7rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        /* Diğer CSS kuralları aynı kalacak */
        :root {
            --primary: #FF2E2E;
            --primary-dark: #CC0000;
            --secondary: #FF6B6B;
            --dark: #0F0F1A;
            --darker: #0A0A12;
            --light: #F0F0F0;
            --gray: #8B8BAA;
            --card-bg: rgba(30, 25, 35, 0.85);
            --card-border: rgba(255, 46, 46, 0.4);
            --success: #10B981;
            --warning: #F59E0B;
            --danger: #EF4444;
            --dragon-red: #FF2E2E;
            --dragon-orange: #FF6B35;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            color: var(--light);
            min-height: 100vh;
            line-height: 1.6;
            overflow-x: hidden;
            position: relative;
        }

        .dragon-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            opacity: 0.08;
            overflow: hidden;
        }

        .dragon-gif {
            width: 100%;
            height: 100%;
            object-fit: cover;
            filter: brightness(0.8) contrast(1.2);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
            position: relative;
            z-index: 1;
        }

        .header {
            text-align: center;
            padding: 60px 0 40px;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at top right, rgba(255, 46, 46, 0.15), transparent 70%);
            z-index: -1;
        }

        .logo-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 15px;
            margin-bottom: 30px;
        }

        .logo-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            box-shadow: 0 10px 25px rgba(255, 46, 46, 0.5);
            transform: rotate(0deg);
            transition: transform 0.5s ease;
        }

        .logo-icon:hover {
            transform: rotate(360deg);
        }

        .logo-text {
            font-family: 'Orbitron', sans-serif;
            font-size: 4rem;
            font-weight: 900;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange), #FF8C42);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 5px 15px rgba(255, 46, 46, 0.5);
            letter-spacing: 2px;
            position: relative;
            display: inline-block;
        }

        .logo-text::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--dragon-red), transparent);
        }

        .nabi-system {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.8rem;
            color: var(--dragon-red);
            margin-top: -10px;
            text-shadow: 0 0 10px rgba(255, 46, 46, 0.7);
            animation: dragonGlow 2s infinite alternate;
        }

        @keyframes dragonGlow {
            from { text-shadow: 0 0 10px rgba(255, 46, 46, 0.7); }
            to { text-shadow: 0 0 20px rgba(255, 46, 46, 1), 0 0 30px rgba(255, 107, 53, 0.5); }
        }

        .tagline {
            font-size: 1.3rem;
            color: var(--gray);
            max-width: 600px;
            margin: 0 auto 30px;
            position: relative;
        }

        .tagline::before, .tagline::after {
            content: '🔥';
            color: var(--dragon-red);
            margin: 0 10px;
        }

        .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 30px;
            flex-wrap: wrap;
        }

        .stat-item {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 15px 25px;
            text-align: center;
            min-width: 150px;
            transform: translateY(0);
            transition: transform 0.3s ease;
        }

        .stat-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(255, 46, 46, 0.2);
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--dragon-red);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--gray);
        }

        .nav-tabs {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 30px 0;
            flex-wrap: wrap;
        }

        .nav-tab {
            padding: 12px 25px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            color: var(--light);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .nav-tab::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 46, 46, 0.2), transparent);
            transition: left 0.5s;
        }

        .nav-tab:hover::before {
            left: 100%;
        }

        .nav-tab.active {
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            box-shadow: 0 5px 15px rgba(255, 46, 46, 0.4);
        }

        .nav-tab:hover:not(.active) {
            background: rgba(255, 46, 46, 0.1);
            border-color: var(--dragon-red);
        }

        .section {
            margin-bottom: 50px;
            display: none;
        }

        .section.active {
            display: block;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .section-title {
            font-size: 2rem;
            font-weight: 700;
            margin: 0 0 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--dragon-red);
            display: flex;
            align-items: center;
            gap: 15px;
            font-family: 'Orbitron', sans-serif;
        }

        .section-title i {
            color: var(--dragon-red);
        }

        .data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }

        .data-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--card-border);
            border-radius: 15px;
            padding: 25px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            transform-style: preserve-3d;
            perspective: 1000px;
        }

        .data-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--dragon-red), var(--dragon-orange));
        }

        .data-card:hover {
            transform: translateY(-8px) rotateX(5deg);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.5);
            border-color: var(--dragon-red);
        }

        .data-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .data-card h3 {
            font-size: 1.3rem;
            margin-bottom: 5px;
            color: var(--light);
        }

        .data-size {
            background: rgba(255, 107, 53, 0.2);
            color: var(--dragon-orange);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .data-description {
            color: var(--gray);
            font-size: 0.95rem;
            margin-bottom: 20px;
            min-height: 40px;
        }

        .data-meta {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
            font-size: 0.85rem;
            color: var(--gray);
        }

        .data-updated {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .data-format {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .download-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            color: white;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            position: relative;
            overflow: hidden;
        }

        .download-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }

        .download-btn:hover::before {
            left: 100%;
        }

        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 15px rgba(255, 46, 46, 0.4);
        }

        .download-btn.premium {
            background: linear-gradient(135deg, #FF8C42, #FF6B35);
        }

        .download-btn.premium:hover {
            box-shadow: 0 7px 15px rgba(255, 140, 66, 0.4);
        }

        .vip-badge {
            position: absolute;
            top: 15px;
            right: 15px;
            background: linear-gradient(135deg, #FFD700, #FFA500);
            color: #000;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 5px;
            box-shadow: 0 3px 10px rgba(255, 215, 0, 0.3);
            z-index: 2;
        }

        .terminal {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid var(--dragon-red);
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
            font-family: 'Courier New', monospace;
            color: var(--dragon-red);
            position: relative;
            overflow: hidden;
        }

        .terminal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(transparent 90%, rgba(255, 46, 46, 0.1) 100%);
            pointer-events: none;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
            border-bottom: 1px solid var(--dragon-orange);
            padding-bottom: 10px;
        }

        .terminal-title {
            font-weight: bold;
        }

        .terminal-content {
            line-height: 1.5;
        }

        .terminal-line {
            margin-bottom: 5px;
        }

        .terminal-prompt {
            color: var(--dragon-orange);
        }

        .footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 50px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--gray);
            position: relative;
        }

        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--dragon-red), transparent);
        }

        .footer-links {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 20px 0;
            flex-wrap: wrap;
        }

        .footer-link {
            color: var(--gray);
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer-link:hover {
            color: var(--dragon-red);
        }

        .status-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--success);
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }

        .turkey-only {
            position: fixed;
            top: 20px;
            left: 20px;
            background: var(--dragon-red);
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }

        .ip-info {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--card-bg);
            color: var(--light);
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            border: 1px solid var(--card-border);
        }

        @media (max-width: 768px) {
            .data-grid {
                grid-template-columns: 1fr;
            }

            .logo-text {
                font-size: 2.5rem;
            }

            .section-title {
                font-size: 1.7rem;
            }

            .stats {
                gap: 15px;
            }

            .stat-item {
                min-width: 120px;
                padding: 12px 15px;
            }

            .stat-number {
                font-size: 1.7rem;
            }
            
            .nav-tabs {
                flex-direction: column;
                align-items: center;
            }
            
            .nav-tab {
                width: 80%;
                text-align: center;
            }
            
            .ip-info {
                bottom: 10px;
                right: 10px;
                left: 10px;
                text-align: center;
            }
            
            .azerbaijan-badge {
                top: 60px;
                left: 20px;
            }
            
            .ddos-protection {
                top: 100px;
                right: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="dragon-bg">
        <img src="https://i.ibb.co/hw1yWdL/red-dragon-yt.gif" alt="Red Dragon" class="dragon-gif">
    </div>
    
    <div class="turkey-only">
        <i class="fas fa-flag"></i> TÜRKİYE IP
    </div>

    <div class="azerbaijan-badge">
        <i class="fas fa-flag"></i> AZERBAYCAN IP
    </div>

    <div class="status-badge">
        <i class="fas fa-shield-alt"></i> GÜVENLİK AKTİF
    </div>
    
    <div class="ddos-protection">
        <i class="fas fa-shield-virus"></i> DDoS KORUMASI
    </div>
    
    <div class="ip-info">
        <i class="fas fa-network-wired"></i> IP: <span id="client-ip">Yükleniyor...</span>
    </div>
    
    <div class="container">
        <div class="header">
            <div class="logo-container">
                <div class="logo-icon">
                    <i class="fas fa-dragon"></i>
                </div>
                <h1 class="logo-text">DATA WEB</h1>
                <div class="nabi-system">NABI SYSTEM</div>
            </div>
            <p class="tagline">Ejderha gücünde veri kaynakları - Türkiye & Azerbaycan için</p>
            
            <div class="terminal">
                <div class="terminal-header">
                    <div class="terminal-title">root@dataweb:~</div>
                    <div class="terminal-status">DRAGON MODE: ACTIVE</div>
                </div>
                <div class="terminal-content">
                    <div class="terminal-line"><span class="terminal-prompt">$</span> system_status --security</div>
                    <div class="terminal-line">> SECURITY_STATUS: <span style="color: var(--dragon-red)">MAXIMUM PROTECTION</span></div>
                    <div class="terminal-line">> ALLOWED_COUNTRIES: <span style="color: var(--dragon-red)">TÜRKİYE & AZERBAYCAN</span></div>
                    <div class="terminal-line">> DDoS_PROTECTION: <span style="color: var(--dragon-red)">ACTIVE</span></div>
                    <div class="terminal-line">> RATE_LIMITING: <span style="color: var(--dragon-red)">ENABLED</span></div>
                    <div class="terminal-line"><span class="terminal-prompt">$</span> _</div>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">2.1B+</div>
                    <div class="stat-label">Toplam Kayıt</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">78</div>
                    <div class="stat-label">Veri Seti</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">2</div>
                    <div class="stat-label">Ülke</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Güvenli Erişim</div>
                </div>
            </div>
        </div>

        <div class="nav-tabs">
            <div class="nav-tab active" data-tab="all">Tüm Veriler</div>
            <div class="nav-tab" data-tab="personal">Kişisel Veriler</div>
            <div class="nav-tab" data-tab="government">Kurumsal Veriler</div>
            <div class="nav-tab" data-tab="social">Sosyal Medya</div>
            <div class="nav-tab" data-tab="premium">VIP Veriler</div>
        </div>

        <!-- Tüm Veriler Section -->
        <div class="section active" id="all">
            <h2 class="section-title">
                <i class="fas fa-database"></i>
                Tüm Veri Setleri (78)
            </h2>
            ''' + generate_data_section('all') + '''
        </div>

        <!-- Diğer section'lar aynı şekilde -->
        <div class="section" id="personal">
            <h2 class="section-title">
                <i class="fas fa-user"></i>
                Kişisel Veri Koleksiyonu
            </h2>
            ''' + generate_data_section('personal') + '''
        </div>

        <div class="section" id="government">
            <h2 class="section-title">
                <i class="fas fa-landmark"></i>
                Kurumsal ve Resmi Veriler
            </h2>
            ''' + generate_data_section('government') + '''
        </div>

        <div class="section" id="social">
            <h2 class="section-title">
                <i class="fas fa-share-alt"></i>
                Sosyal Medya Verileri
            </h2>
            ''' + generate_data_section('social') + '''
        </div>

        <div class="section" id="premium">
            <h2 class="section-title">
                <i class="fas fa-crown"></i>
                VIP Veri Setleri
            </h2>
            ''' + generate_data_section('premium') + '''
        </div>

        <div class="footer">
            <div class="footer-links">
                <a href="#" class="footer-link">Gizlilik Politikası</a>
                <a href="#" class="footer-link">Kullanım Şartları</a>
                <a href="#" class="footer-link">İletişim</a>
                <a href="#" class="footer-link">SSS</a>
            </div>
            <p>© 2024 Nabi System - Premium Data Web. Tüm hakları saklıdır.</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #94A3B8;">Türkiye & Azerbaycan IP'lerine özel - Maximum güvenlik ile</p>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.nav-tab');
            const sections = document.querySelectorAll('.section');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    const targetTab = this.getAttribute('data-tab');
                    
                    tabs.forEach(t => t.classList.remove('active'));
                    sections.forEach(s => s.classList.remove('active'));
                    
                    this.classList.add('active');
                    document.getElementById(targetTab).classList.add('active');
                });
            });
            
            const dataCards = document.querySelectorAll('.data-card');
            dataCards.forEach(card => {
                card.addEventListener('mouseenter', function() {
                    this.style.transform = 'translateY(-8px) rotateX(5deg)';
                });
                
                card.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0) rotateX(0)';
                });
            });
            
            // IP bilgisini göster
            fetch('/get_ip')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('client-ip').textContent = data.ip;
                })
                .catch(error => {
                    document.getElementById('client-ip').textContent = 'Bilinmiyor';
                });
        });
    </script>
</body>
</html>'''

@app.before_request
def before_request():
    """Her istekten önce güvenlik kontrolleri"""
    client_ip = get_real_ip()
    
    # Debug için IP'yi yazdır
    print(f"Gelen istek - Gerçek IP: {client_ip}, Remote Addr: {request.remote_addr}")
    
    # DDoS koruma kontrolü
    if not check_ddos_pattern(client_ip):
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Erişim Engellendi</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: #0F0F1A; 
                    color: white; 
                    text-align: center; 
                    padding: 50px; 
                }
                .error-box {
                    background: rgba(255, 46, 46, 0.1);
                    border: 2px solid #FF2E2E;
                    padding: 30px;
                    border-radius: 10px;
                    max-width: 500px;
                    margin: 0 auto;
                }
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>🚫 DDoS Koruması</h1>
                <p>Çok fazla istek gönderdiniz. DDoS saldırısı tespit edildi.</p>
                <p>IP Adresiniz: <strong>''' + client_ip + '''</strong></p>
                <p style="margin-top: 20px; font-size: 0.9rem; color: #94A3B8;">
                    Erişiminiz 4 saat süreyle engellenmiştir.
                </p>
            </div>
        </body>
        </html>
        ''', 429
    
    # Sadece Türkiye ve Azerbaycan IP kontrolü
    if not check_allowed_ip(client_ip):
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Erişim Engellendi</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    background: #0F0F1A; 
                    color: white; 
                    text-align: center; 
                    padding: 50px; 
                }}
                .error-box {{
                    background: rgba(255, 46, 46, 0.1);
                    border: 2px solid #FF2E2E;
                    padding: 30px;
                    border-radius: 10px;
                    max-width: 500px;
                    margin: 0 auto;
                }}
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>🚫 Erişim Engellendi</h1>
                <p>Bu siteye sadece Türkiye ve Azerbaycan IP adreslerinden erişim sağlanabilir.</p>
                <p>IP Adresiniz: <strong>{client_ip}</strong></p>
                <p style="margin-top: 20px; font-size: 0.9rem; color: #94A3B8;">
                    Desteklenen ülkeler: Türkiye, Azerbaycan
                </p>
            </div>
        </body>
        </html>
        ''', 403
    
    # VPN/Proxy kontrolü
    if check_vpn_proxy(client_ip):
        return jsonify({'error': 'VPN/Proxy tespit edildi. Erişim engellendi.'}), 403
    
    # Şüpheli header kontrolü
    if check_suspicious_headers(request.headers):
        return jsonify({'error': 'Şüpheli header tespit edildi. Erişim engellendi.'}), 403
    
    # User Agent kontrolü
    user_agent_ok, user_agent_msg = check_user_agent(request.headers.get('User-Agent'))
    if not user_agent_ok:
        return jsonify({'error': user_agent_msg}), 403
    
    # Session kontrolü
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = create_user_session(request)
        response = make_response('''<html><body><script>location.reload();</script></body></html>''')
        response.set_cookie('session_id', session_id, httponly=True, max_age=3600)
        return response
    
    # Session doğrulama
    session_ok, session_msg = validate_session(session_id, request)
    if not session_ok:
        response = make_response('''<html><body><script>location.reload();</script></body></html>''')
        response.set_cookie('session_id', '', expires=0)
        return response
    
    # Gelişmiş rate limiting
    rate_ok, rate_msg = advanced_rate_limit(client_ip, session_id)
    if not rate_ok:
        return jsonify({'error': rate_msg}), 429
    
    user_sessions[session_id]['request_count'] += 1

@app.route('/')
def home():
    """Ana sayfa - Data indirme sitesi"""
    client_ip = get_real_ip()
    print(f"Ana sayfa isteği - IP: {client_ip}")
    
    session_id = create_user_session(request)
    response = make_response(HTML_TEMPLATE)
    response.set_cookie('session_id', session_id, httponly=True, max_age=3600)
    return response

@app.route('/get_ip')
def get_ip():
    """Client IP'sini döndür"""
    return jsonify({'ip': get_real_ip()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
