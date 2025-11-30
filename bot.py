from flask import Flask, request, jsonify, make_response
import time
from collections import defaultdict
import hashlib
import uuid
import ipaddress

app = Flask(__name__)

# Güvenlik Konfigürasyonları
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 8
RATE_LIMIT_BLOCK_DURATION = 3600

# IP bazlı rate limiting
request_log = defaultdict(list)
blocked_ips = {}
user_sessions = {}

# Türkiye IP aralıkları
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

# VPN/Proxy IP listeleri
VPN_IP_RANGES = [
    '185.159.131.', '45.137.21.', '193.29.13.', '91.199.117.',
    '45.95.147.', '185.220.101.', '185.165.190.', '45.142.214.'
]

# Şüpheli User Agent'lar
SUSPICIOUS_USER_AGENTS = [
    'python', 'requests', 'curl', 'wget', 'scrapy', 'bot', 'crawler', 
    'spider', 'monitor', 'headless', 'phantom', 'selenium', 'automation'
]

# Geçerli User Agent'lar
VALID_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
]

def ip_to_int(ip):
    """IP adresini integer'a çevir"""
    return int(ipaddress.IPv4Address(ip))

def check_turkey_ip(ip):
    """IP'nin Türkiye'den olup olmadığını kontrol et"""
    try:
        ip_int = ip_to_int(ip)
        for ip_range in TURKEY_IP_RANGES:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            if ip_int >= int(network[0]) and ip_int <= int(network[-1]):
                return True
        return False
    except:
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
        'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr'
    ]
    
    for header in suspicious_headers:
        if header in headers:
            return True
    return False

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

def check_rate_limit(ip, session_id):
    """Rate limiting kontrolü"""
    now = time.time()
    
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return False, "IP adresiniz 1 saat süreyle bloklanmıştır."
        else:
            del blocked_ips[ip]
    
    window_start = now - RATE_LIMIT_WINDOW
    request_log[session_id] = [timestamp for timestamp in request_log.get(session_id, []) if timestamp > window_start]
    
    if len(request_log[session_id]) >= RATE_LIMIT_MAX_REQUESTS:
        blocked_ips[ip] = now + RATE_LIMIT_BLOCK_DURATION
        return False, "Rate limit aşıldı. IP adresiniz 1 saat süreyle bloklanmıştır."
    
    request_log[session_id].append(now)
    return True, "OK"

def create_user_session(request):
    """Kullanıcı session'ı oluşturma"""
    session_id = str(uuid.uuid4())
    fingerprint = generate_user_fingerprint(request)
    
    user_sessions[session_id] = {
        'fingerprint': fingerprint,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'created_at': time.time(),
        'request_count': 0
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
    
    return True, "OK"

def generate_user_fingerprint(request):
    """Kullanıcı fingerprint oluşturma"""
    components = [
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.headers.get('Accept', ''),
        request.remote_addr
    ]
    fingerprint_string = '|'.join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

# HTML TEMPLATE (Sadece Data İndirme Sitesi)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nabi System - Premium Data Web</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
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
        }
    </style>
</head>
<body>
    <div class="dragon-bg">
        <img src="https://i.ibb.co/hw1yWdL/red-dragon-yt.gif" alt="Red Dragon" class="dragon-gif">
    </div>
    
    <div class="turkey-only">
        <i class="fas fa-flag"></i> SADECE TÜRKİYE IP
    </div>

    <div class="status-badge">
        <i class="fas fa-shield-alt"></i> GÜVENLİK AKTİF
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
            <p class="tagline">Ejderha gücünde veri kaynakları - Sadece gerçekler için</p>
            
            <div class="terminal">
                <div class="terminal-header">
                    <div class="terminal-title">root@dataweb:~</div>
                    <div class="terminal-status">DRAGON MODE: ACTIVE</div>
                </div>
                <div class="terminal-content">
                    <div class="terminal-line"><span class="terminal-prompt">$</span> system_status --dragon</div>
                    <div class="terminal-line">> DATA_WEB_STATUS: <span style="color: var(--dragon-red)">DRAGON POWERED</span></div>
                    <div class="terminal-line">> DATASETS_AVAILABLE: <span style="color: var(--dragon-red)">78</span></div>
                    <div class="terminal-line">> TOTAL_RECORDS: <span style="color: var(--dragon-red)">2.1B+</span></div>
                    <div class="terminal-line">> SECURITY_LEVEL: <span style="color: var(--dragon-red)">DRAGON FIRE</span></div>
                    <div class="terminal-line"><span class="terminal-prompt">$</span> _</div>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">2.1B+</div>
                    <div class="stat-label">Toplam Kayıt</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">78+</div>
                    <div class="stat-label">Veri Seti</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">24/7</div>
                    <div class="stat-label">Aktif Sistem</div>
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
                Tüm Veri Setleri
            </h2>
            
            <div class="data-grid">
                <!-- GSM Verileri -->
                <div class="data-card">
                    <div class="vip-badge">
                        <i class="fas fa-crown"></i> VIP
                    </div>
                    <div class="data-card-header">
                        <h3>200m Gsm</h3>
                        <span class="data-size">4.2 GB</span>
                    </div>
                    <p class="data-description">Türkiye'nin en kapsamlı GSM veritabanı</p>
                    <div class="data-meta">
                        <div class="data-updated">
                            <i class="far fa-calendar-alt"></i>
                            <span>Güncelleme: 01.07.2024</span>
                        </div>
                        <div class="data-format">
                            <i class="far fa-file-alt"></i>
                            <span>CSV/ZIP</span>
                        </div>
                    </div>
                    <a href="https://drive.google.com/file/d/1oo6_RJcd9qWywx6l0yvol9cRXbOyQdow/view?usp=sharing" target="_blank" class="download-btn premium">
                        <i class="fas fa-download"></i> Nabi System VIP İndir
                    </a>
                </div>

                <div class="data-card">
                    <div class="vip-badge">
                        <i class="fas fa-crown"></i> VIP
                    </div>
                    <div class="data-card-header">
                        <h3>120m Gsm</h3>
                        <span class="data-size">2.7 GB</span>
                    </div>
                    <p class="data-description">GSM abone veritabanı</p>
                    <div class="data-meta">
                        <div class="data-updated">
                            <i class="far fa-calendar-alt"></i>
                            <span>Güncelleme: 20.05.2024</span>
                        </div>
                        <div class="data-format">
                            <i class="far fa-file-alt"></i>
                            <span>CSV/ZIP</span>
                        </div>
                    </div>
                    <a href="https://drive.google.com/file/d/19vEG1Bag-TeB0G6zH_qGS5MiCGBotcMg/view?usp=sharing" target="_blank" class="download-btn premium">
                        <i class="fas fa-download"></i> Nabi System VIP İndir
                    </a>
                </div>

                <!-- Diğer veri kartları buraya gelecek -->
                <!-- Kısaltıyorum, gerisini aynı şekilde ekleyebilirsin -->
                
            </div>
        </div>

        <!-- Diğer section'lar burada olacak -->
        <!-- Kişisel Veriler -->
        <div class="section" id="personal">
            <h2 class="section-title">
                <i class="fas fa-user"></i>
                Kişisel Veri Koleksiyonu
            </h2>
            <div class="data-grid">
                <!-- Kişisel veriler burada -->
            </div>
        </div>

        <!-- Kurumsal Veriler -->
        <div class="section" id="government">
            <h2 class="section-title">
                <i class="fas fa-landmark"></i>
                Kurumsal ve Resmi Veriler
            </h2>
            <div class="data-grid">
                <!-- Kurumsal veriler burada -->
            </div>
        </div>

        <!-- Sosyal Medya -->
        <div class="section" id="social">
            <h2 class="section-title">
                <i class="fas fa-share-alt"></i>
                Sosyal Medya Verileri
            </h2>
            <div class="data-grid">
                <!-- Sosyal medya verileri burada -->
            </div>
        </div>

        <!-- VIP Veriler -->
        <div class="section" id="premium">
            <h2 class="section-title">
                <i class="fas fa-crown"></i>
                VIP Veri Setleri
            </h2>
            <div class="data-grid">
                <!-- VIP veriler burada -->
            </div>
        </div>

        <div class="footer">
            <div class="footer-links">
                <a href="#" class="footer-link">Gizlilik Politikası</a>
                <a href="#" class="footer-link">Kullanım Şartları</a>
                <a href="#" class="footer-link">İletişim</a>
                <a href="#" class="footer-link">SSS</a>
            </div>
            <p>© 2024 Nabi System - Premium Data Web. Tüm hakları saklıdır.</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #94A3B8;">Ejderha gücünde veri erişimi - Sadece seçilmişler için</p>
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
        });
    </script>
</body>
</html>'''

@app.before_request
def before_request():
    """Her istekten önce güvenlik kontrolleri"""
    client_ip = request.remote_addr
    
    # Sadece Türkiye IP kontrolü
    if not check_turkey_ip(client_ip):
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
                <h1>🚫 Erişim Engellendi</h1>
                <p>Bu siteye sadece Türkiye IP adreslerinden erişim sağlanabilir.</p>
                <p>IP Adresiniz: <strong>''' + client_ip + '''</strong></p>
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
    
    # Rate limiting
    rate_ok, rate_msg = check_rate_limit(client_ip, session_id)
    if not rate_ok:
        return jsonify({'error': rate_msg}), 429
    
    user_sessions[session_id]['request_count'] += 1

@app.route('/')
def home():
    """Ana sayfa - Data indirme sitesi"""
    session_id = create_user_session(request)
    response = make_response(HTML_TEMPLATE)
    response.set_cookie('session_id', session_id, httponly=True, max_age=3600)
    return response

@app.route('/download/<path:filename>')
def download_file(filename):
    """Dosya indirme endpoint'i (isteğe bağlı)"""
    # Burada dosya indirme logiği eklenebilir
    return "Download endpoint", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
