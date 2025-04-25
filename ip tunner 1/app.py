from flask import Flask, render_template, request, jsonify
import subprocess
import socket
import pythonping
import json
import re
import os
import time
import concurrent.futures
import requests
import ssl
import whois
import dns.resolver
import dns.reversename
from datetime import datetime
from urllib.parse import urlparse
import socket
import ipaddress
import langdetect
from langdetect import detect

app = Flask(__name__)

def is_valid_ip(ip):
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip):
        return True
    elif re.match(ipv6_pattern, ip):
        return True
    return False

def perform_ping(ip):
    try:
        result = pythonping.ping(ip, count=4)
        return {
            'success': True,
            'min_latency': result.rtt_min_ms,
            'max_latency': result.rtt_max_ms,
            'avg_latency': result.rtt_avg_ms,
            'packet_loss': result.packet_loss
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def perform_mtr(ip):
    try:
        # Using Windows pathping command as an alternative to MTR
        result = subprocess.run(['pathping', '-n', '-q', '1', '-p', '100', ip], 
                              capture_output=True, text=True, timeout=30)
        return {'success': True, 'result': result.stdout}
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Pathping timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def perform_traceroute(ip):
    try:
        # Using Windows tracert command
        result = subprocess.run(['tracert', ip], capture_output=True, text=True)
        return {'success': True, 'result': result.stdout}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = 'unknown'
            return {'port': port, 'status': 'open', 'service': service}
        return {'port': port, 'status': 'closed', 'service': 'unknown'}
    except Exception as e:
        return {'port': port, 'status': 'error', 'service': 'unknown', 'error': str(e)}

def perform_port_scan(ip):
    try:
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 3306, 5432, 27017]
        open_ports = []
        
        # Use ThreadPoolExecutor for concurrent port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result['status'] == 'open':
                    open_ports.append(result)
        
        return {'success': True, 'open_ports': open_ports}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def check_firewall(ip):
    try:
        # Enhanced firewall detection using multiple methods
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389]
        results = []
        
        for port in common_ports:
            try:
                # Try TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                # Try UDP connection
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.settimeout(2)
                udp_sock.sendto(b'', (ip, port))
                try:
                    udp_sock.recvfrom(1024)
                    udp_status = 'open'
                except socket.timeout:
                    udp_status = 'filtered'
                udp_sock.close()
                
                if result == 0:
                    results.append({
                        'port': port,
                        'status': 'open',
                        'protocol': 'TCP'
                    })
                else:
                    results.append({
                        'port': port,
                        'status': 'filtered',
                        'protocol': 'TCP'
                    })
                
                results.append({
                    'port': port,
                    'status': udp_status,
                    'protocol': 'UDP'
                })
                
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'protocol': 'TCP/UDP',
                    'error': str(e)
                })
        
        # Analyze results for firewall patterns
        firewall_detected = False
        firewall_type = 'Unknown'
        
        # Check for common firewall patterns
        if all(result['status'] == 'filtered' for result in results):
            firewall_detected = True
            firewall_type = 'Strict Firewall (All ports filtered)'
        elif any(result['status'] == 'open' for result in results):
            firewall_detected = True
            firewall_type = 'Selective Firewall (Some ports open)'
        
        return {
            'success': True,
            'results': results,
            'firewall_detected': firewall_detected,
            'firewall_type': firewall_type
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def check_dns_records(domain):
    try:
        results = {}
        
        # Check A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            results['a_records'] = [str(record) for record in a_records]
        except Exception as e:
            results['a_records'] = {'error': str(e)}
            
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['mx_records'] = [str(record) for record in mx_records]
        except Exception as e:
            results['mx_records'] = {'error': str(e)}
            
        # Check TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            results['txt_records'] = [str(record) for record in txt_records]
        except Exception as e:
            results['txt_records'] = {'error': str(e)}
            
        # Check NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results['ns_records'] = [str(record) for record in ns_records]
        except Exception as e:
            results['ns_records'] = {'error': str(e)}
            
        return results
    except Exception as e:
        return {'error': str(e)}

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5, verify=True)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set')
        }
        
        return security_headers
    except Exception as e:
        return {'error': str(e)}

def check_ip_reputation(ip):
    try:
        # Check if IP is in private range
        is_private = ipaddress.ip_address(ip).is_private
        
        # Check if IP is in reserved range
        is_reserved = ipaddress.ip_address(ip).is_reserved
        
        # Check if IP is in multicast range
        is_multicast = ipaddress.ip_address(ip).is_multicast
        
        # Try to get hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = 'Unknown'
            
        return {
            'is_private': is_private,
            'is_reserved': is_reserved,
            'is_multicast': is_multicast,
            'hostname': hostname
        }
    except Exception as e:
        return {'error': str(e)}

def get_ip_geolocation(ip):
    try:
        # Using free IP geolocation service
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'region_name': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'zip': data.get('zip', 'Unknown'),
                'lat': data.get('lat', 'Unknown'),
                'lon': data.get('lon', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'as': data.get('as', 'Unknown')
            }
        return {'error': 'Could not fetch geolocation data'}
    except Exception as e:
        return {'error': str(e)}

def detect_database(url, content, headers):
    try:
        database_info = {
            'type': 'Unknown',
            'version': 'Unknown',
            'indicators': []
        }
        
        # Common database indicators
        db_indicators = {
            'MySQL': [
                'mysql', 'mysqli', 'mysql_connect',
                'mysql_fetch_array', 'mysql_error',
                'mysql_select_db', 'mysql_query'
            ],
            'PostgreSQL': [
                'postgres', 'pg_connect', 'pg_query',
                'pg_fetch_array', 'postgresql'
            ],
            'MongoDB': [
                'mongodb', 'mongoose', 'mongo.connect',
                'mongodb+srv://'
            ],
            'SQLite': [
                'sqlite', 'sqlite3', '.db file',
                'sqlite_connect'
            ],
            'Microsoft SQL Server': [
                'mssql', 'sqlsrv', 'sql server',
                'microsoft sql', 'ms sql'
            ],
            'Oracle': [
                'oracle', 'oci_connect', 'oracle_connect',
                'oracle_query'
            ]
        }
        
        # Check headers for database indicators
        server_header = headers.get('Server', '').lower()
        x_powered_by = headers.get('X-Powered-By', '').lower()
        
        # Check content for database indicators
        content_lower = content.lower()
        
        # Check for database connection strings in content
        connection_patterns = {
            'MySQL': r'mysql://[^"\s]+|mysqli_connect\([^)]+\)',
            'PostgreSQL': r'postgres://[^"\s]+|pg_connect\([^)]+\)',
            'MongoDB': r'mongodb://[^"\s]+|mongodb\+srv://[^"\s]+',
            'SQLite': r'sqlite://[^"\s]+|\.db\b',
            'MSSQL': r'sqlsrv://[^"\s]+|mssql://[^"\s]+',
            'Oracle': r'oracle://[^"\s]+|oci_connect\([^)]+\)'
        }
        
        found_dbs = set()
        
        # Check headers
        for db_type, indicators in db_indicators.items():
            if any(indicator in server_header for indicator in indicators) or \
               any(indicator in x_powered_by for indicator in indicators):
                found_dbs.add(db_type)
                database_info['indicators'].append(f'Found in headers: {db_type}')
        
        # Check content
        for db_type, indicators in db_indicators.items():
            if any(indicator in content_lower for indicator in indicators):
                found_dbs.add(db_type)
                database_info['indicators'].append(f'Found in content: {db_type}')
        
        # Check connection strings
        for db_type, pattern in connection_patterns.items():
            if re.search(pattern, content):
                found_dbs.add(db_type)
                database_info['indicators'].append(f'Found connection string: {db_type}')
        
        # Check for common error messages
        error_messages = {
            'MySQL': [
                'mysql_fetch_array()', 'mysql_connect()',
                'Access denied for user', 'MySQL server has gone away'
            ],
            'PostgreSQL': [
                'pg_fetch_array()', 'pg_connect()',
                'PostgreSQL query failed'
            ],
            'MongoDB': [
                'MongoDB connection failed', 'MongoDB error',
                'MongoDB server selection'
            ],
            'SQLite': [
                'SQLite error', 'SQLite database is locked',
                'SQLite format'
            ],
            'Microsoft SQL Server': [
                'SQL Server error', 'SQL Server connection',
                'Microsoft SQL Server'
            ],
            'Oracle': [
                'ORA-', 'Oracle error', 'Oracle connection'
            ]
        }
        
        for db_type, errors in error_messages.items():
            if any(error in content for error in errors):
                found_dbs.add(db_type)
                database_info['indicators'].append(f'Found error message: {db_type}')
        
        if found_dbs:
            database_info['type'] = ', '.join(found_dbs)
        
        return database_info
    except Exception as e:
        return {
            'type': 'Unknown',
            'version': 'Unknown',
            'error': str(e)
        }

def analyze_website_generation(url, content):
    try:
        generation_info = {
            'framework': 'Unknown',
            'cms': 'Unknown',
            'server': 'Unknown',
            'technologies': [],
            'database': {}
        }
        
        # Get headers for analysis
        try:
            response = requests.head(url, timeout=5)
            headers = response.headers
            generation_info['server'] = headers.get('Server', 'Unknown')
            
            # Detect database
            generation_info['database'] = detect_database(url, content, headers)
        except:
            pass
        
        # Check for common frameworks and CMS
        framework_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/all'],
            'Joomla': ['joomla', 'components/com_'],
            'React': ['react', 'react-dom'],
            'Angular': ['ng-', 'angular'],
            'Vue': ['vue', 'vue-router'],
            'Laravel': ['laravel', 'artisan.js'],
            'Django': ['django', 'csrfmiddlewaretoken']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in content.lower() for pattern in patterns):
                generation_info['technologies'].append(framework)
                if framework in ['WordPress', 'Drupal', 'Joomla']:
                    generation_info['cms'] = framework
                else:
                    generation_info['framework'] = framework
        
        return generation_info
    except Exception as e:
        return {'error': str(e)}

def detect_content_language(content):
    try:
        # Extract text content (remove HTML tags)
        text = re.sub(r'<[^>]+>', '', content)
        # Remove extra whitespace
        text = ' '.join(text.split())
        # Detect language
        language = detect(text)
        return language
    except:
        return 'Unknown'

def check_website_safety(url):
    try:
        # Parse URL and ensure it has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Initialize results dictionary
        results = {
            'url': url,
            'domain': domain,
            'is_safe': True,
            'checks': {}
        }
        
        # Get website content for analysis
        try:
            response = requests.get(url, timeout=5, verify=True)
            content = response.text
        except Exception as e:
            content = ''
            results['checks']['content'] = {'error': str(e)}
        
        # Check 1: Location and Server Information
        try:
            ip = socket.gethostbyname(domain)
            results['checks']['location'] = get_ip_geolocation(ip)
            
            # Get server location from headers
            try:
                response = requests.head(url, timeout=5)
                server_location = response.headers.get('X-Server-Location', 'Unknown')
                results['checks']['location']['server_location'] = server_location
            except:
                pass
        except Exception as e:
            results['checks']['location'] = {'error': str(e)}
        
        # Check 2: Website Generation and Technology
        results['checks']['generation'] = analyze_website_generation(url, content)
        
        # Check 3: Content Language
        if content:
            results['checks']['language'] = {
                'detected': detect_content_language(content)
            }
        
        # Check 4: HTTPS and SSL
        try:
            response = requests.get(url, timeout=5, verify=True)
            results['checks']['https'] = {
                'available': True,
                'status_code': response.status_code
            }
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    results['checks']['ssl_certificate'] = {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                        'days_until_expiry': days_until_expiry,
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher()[0]
                    }
                    
                    if days_until_expiry < 30:
                        results['is_safe'] = False
                        results['checks']['ssl_certificate']['warning'] = 'Certificate expires soon'
        except requests.exceptions.SSLError:
            results['checks']['https'] = {
                'available': False,
                'error': 'SSL certificate error'
            }
            results['is_safe'] = False
        except Exception as e:
            results['checks']['https'] = {
                'available': False,
                'error': str(e)
            }
            results['is_safe'] = False
        
        # Check 5: DNS Records
        results['checks']['dns_records'] = check_dns_records(domain)
        
        # Check 6: Security Headers
        results['checks']['security_headers'] = check_security_headers(url)
        
        # Check 7: IP Reputation
        try:
            ip = socket.gethostbyname(domain)
            results['checks']['ip_reputation'] = check_ip_reputation(ip)
        except Exception as e:
            results['checks']['ip_reputation'] = {'error': str(e)}
        
        # Check 8: WHOIS information
        try:
            w = whois.whois(domain)
            results['checks']['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'registrant_name': w.name,
                'registrant_organization': w.org,
                'registrant_country': w.country
            }
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                age_days = (datetime.now() - creation_date).days
                if age_days < 180:
                    results['is_safe'] = False
                    results['checks']['whois']['warning'] = 'Domain is relatively new'
        except Exception as e:
            results['checks']['whois'] = {
                'error': str(e)
            }
        
        # Check 9: Content Analysis
        suspicious_patterns = [
            'phishing', 'malware', 'scam', 'fraud',
            'hack', 'exploit', 'virus', 'trojan',
            'password', 'login', 'account', 'verify',
            'suspicious', 'alert', 'warning', 'danger'
        ]
        
        if content:
            found_patterns = [pattern for pattern in suspicious_patterns if pattern in content.lower()]
            iframe_count = content.count('<iframe')
            script_count = content.count('<script')
            form_count = content.count('<form')
            
            results['checks']['content_analysis'] = {
                'suspicious_patterns_found': len(found_patterns) > 0,
                'patterns': found_patterns,
                'iframe_count': iframe_count,
                'script_count': script_count,
                'form_count': form_count
            }
            
            if found_patterns or iframe_count > 3 or script_count > 10:
                results['is_safe'] = False
        
        return results
        
    except Exception as e:
        return {
            'url': url,
            'is_safe': False,
            'error': str(e)
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/diagnose', methods=['POST'])
def diagnose():
    ip = request.form.get('ip')
    
    if not ip or not is_valid_ip(ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    results = {
        'ping': perform_ping(ip),
        'mtr': perform_mtr(ip),
        'traceroute': perform_traceroute(ip),
        'port_scan': perform_port_scan(ip),
        'firewall': check_firewall(ip)
    }
    
    return jsonify(results)

@app.route('/check_website', methods=['POST'])
def check_website():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    results = check_website_safety(url)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True) 