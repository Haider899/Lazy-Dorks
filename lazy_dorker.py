#!/usr/bin/env python3
"""
LAZY DORKER - Advanced Google & GitHub Dorking Tool

Author: Haider (Lazy_Hacks)
GitHub: https://github.com/Lazy-Hacks/lazy-dorker
Description: Powerful automated Google & GitHub dorking for security researchers
License: MIT
Version: 2.1
"""

import requests
import time
import random
import json
import os
import re
import sys
from urllib.parse import quote, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

class Colors:
    """ANSI color codes for console output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    ORANGE = '\033[38;5;208m'
    ENDC = '\033[0m'

class LazyDorker:
    """
    Advanced Google & GitHub Dorking Tool for security researchers
    
    Features:
    - 300+ advanced dorks across multiple categories
    - Google dorking with advanced operators
    - GitHub dorking for exposed secrets and code
    - Multi-search engine support
    - Real content verification
    - Smart rate limiting with random delays
    - Comprehensive reporting
    """
    
    def __init__(self):
        """Initialize the dorking tool with configurations"""
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
        ]
        
        # Advanced Google dork categories
        self.google_dork_categories = {
            'sensitive_directories': [
                'site:{} inurl:"admin"',
                'site:{} inurl:"login"',
                'site:{} inurl:"config"',
                'site:{} inurl:"backup"',
                'site:{} inurl:"database"',
                'site:{} inurl:"password"',
                'site:{} inurl:"secret"',
                'site:{} inurl:"api"',
                'site:{} inurl:"debug"',
                'site:{} inurl:"test"',
                'site:{} inurl:"git"',
                'site:{} inurl:"svn"',
                'site:{} inurl:"env"',
                'site:{} inurl:"aws"',
                'site:{} inurl:"ssh"',
                'site:{} inurl:"ftp"',
                'site:{} inurl:"cpanel"',
                'site:{} inurl:"phpmyadmin"',
                'site:{} inurl:"webmin"',
                'site:{} inurl:"administrator"'
            ],
            'exposed_config_files': [
                'site:{} ext:env DB_PASSWORD',
                'site:{} ext:yml database',
                'site:{} ext:yaml password',
                'site:{} ext:json API_KEY',
                'site:{} ext:xml password',
                'site:{} ext:conf password',
                'site:{} ext:config password',
                'site:{} ext:ini password',
                'site:{} "wp-config.php"',
                'site:{} "config.php"',
                'site:{} "settings.py"',
                'site:{} "config.json"',
                'site:{} ".env"',
                'site:{} ".htpasswd"',
                'site:{} ".htaccess"',
                'site:{} "robots.txt"',
                'site:{} "web.config"',
                'site:{} "package.json"',
                'site:{} "composer.json"',
                'site:{} "pom.xml"'
            ],
            'database_exposures': [
                'site:{} ext:sql "INSERT INTO"',
                'site:{} ext:sql "CREATE TABLE"',
                'site:{} ext:sql "DROP TABLE"',
                'site:{} ext:sql "mysql_dump"',
                'site:{} ext:sql "pg_dump"',
                'site:{} ext:sql "mysqldump"',
                'site:{} ext:sql "phpMyAdmin"',
                'site:{} ext:db "SQLite"',
                'site:{} ext:mdb "database"',
                'site:{} ext:accdb "password"',
                'site:{} "database backup"',
                'site:{} "sql dump"',
                'site:{} "db backup"',
                'site:{} inurl:"phpmyadmin"',
                'site:{} inurl:"adminer"',
                'site:{} inurl:"mysql"',
                'site:{} inurl:"pma"'
            ],
            'backup_files': [
                'site:{} ext:bak "backup"',
                'site:{} ext:zip "backup"',
                'site:{} ext:tar "backup"',
                'site:{} ext:gz "backup"',
                'site:{} ext:7z "backup"',
                'site:{} ext:rar "backup"',
                'site:{} ext:sql "backup"',
                'site:{} ext:dump "database"',
                'site:{} "backup.zip"',
                'site:{} "backup.tar"',
                'site:{} "backup.sql"',
                'site:{} "database.zip"',
                'site:{} "dump.sql"',
                'site:{} "backup_"',
                'site:{} "_backup"',
                'site:{} "backup-"',
                'site:{} "-backup"'
            ],
            'log_files': [
                'site:{} ext:log "error"',
                'site:{} ext:log "password"',
                'site:{} ext:log "DEBUG"',
                'site:{} ext:log "exception"',
                'site:{} ext:txt "error.log"',
                'site:{} ext:log "stacktrace"',
                'site:{} "debug.log"',
                'site:{} "error.log"',
                'site:{} "access.log"',
                'site:{} "apache.log"',
                'site:{} "nginx.log"',
                'site:{} "laravel.log"',
                'site:{} "debug" ext:txt'
            ],
            'developer_files': [
                'site:{} inurl:".git" "index of"',
                'site:{} inurl:".svn" "index of"',
                'site:{} inurl:".hg" "index of"',
                'site:{} inurl:".bzr" "index of"',
                'site:{} ".gitignore"',
                'site:{} "README.md"',
                'site:{} "CHANGELOG"',
                'site:{} "LICENSE"',
                'site:{} "Dockerfile"',
                'site:{} "docker-compose.yml"',
                'site:{} "Jenkinsfile"',
                'site:{} "travis.yml"',
                'site:{} ".travis.yml"',
                'site:{} "circleci"',
                'site:{} "bitbucket-pipelines.yml"'
            ],
            'admin_interfaces': [
                'site:{} intitle:"admin"',
                'site:{} intitle:"login"',
                'site:{} intitle:"administrator"',
                'site:{} intitle:"dashboard"',
                'site:{} intitle:"control panel"',
                'site:{} intitle:"webmail"',
                'site:{} intitle:"cpanel"',
                'site:{} intitle:"plesk"',
                'site:{} intitle:"phpmyadmin"',
                'site:{} intitle:"webmin"',
                'site:{} intitle:"router"',
                'site:{} intitle:"firewall"',
                'site:{} intitle:"manage"',
                'site:{} intitle:"system"',
                'site:{} intitle:"config"'
            ],
            'vulnerable_files': [
                'site:{} inurl:"phpinfo.php"',
                'site:{} inurl:"test.php"',
                'site:{} inurl:"debug.php"',
                'site:{} inurl:"info.php"',
                'site:{} inurl:"example.php"',
                'site:{} inurl:"demo.php"',
                'site:{} "phpinfo()"',
                'site:{} "test" ext:php',
                'site:{} "debug" ext:php',
                'site:{} inurl:"shell.php"',
                'site:{} inurl:"cmd.php"',
                'site:{} inurl:"backdoor.php"'
            ],
            'exposed_documents': [
                'site:{} filetype:pdf "confidential"',
                'site:{} filetype:doc "password"',
                'site:{} filetype:docx "secret"',
                'site:{} filetype:xls "financial"',
                'site:{} filetype:xlsx "salary"',
                'site:{} filetype:csv "password"',
                'site:{} filetype:txt "username"',
                'site:{} filetype:rtf "confidential"',
                'site:{} filetype:odt "draft"',
                'site:{} filetype:ppt "presentation"',
                'site:{} "confidential" filetype:pdf',
                'site:{} "secret" filetype:doc',
                'site:{} "internal" filetype:xls'
            ],
            'api_endpoints': [
                'site:{} inurl:"/api/"',
                'site:{} inurl:"/v1/"',
                'site:{} inurl:"/v2/"',
                'site:{} inurl:"/graphql"',
                'site:{} inurl:"/rest/"',
                'site:{} inurl:"/soap/"',
                'site:{} inurl:"/json/"',
                'site:{} inurl:"/xml/"',
                'site:{} "swagger"',
                'site:{} "openapi"',
                'site:{} "api documentation"',
                'site:{} "postman"',
                'site:{} "endpoint"',
                'site:{} "web service"'
            ],
            'authentication_pages': [
                'site:{} inurl:"login"',
                'site:{} inurl:"signin"',
                'site:{} inurl:"auth"',
                'site:{} inurl:"authenticate"',
                'site:{} inurl:"logout"',
                'site:{} inurl:"register"',
                'site:{} inurl:"signup"',
                'site:{} inurl:"password"',
                'site:{} inurl:"reset"',
                'site:{} inurl:"forgot"',
                'site:{} inurl:"recover"',
                'site:{} "login.php"',
                'site:{} "login.asp"',
                'site:{} "login.aspx"'
            ],
            'sensitive_keywords': [
                'site:{} "password" "username"',
                'site:{} "api_key"',
                'site:{} "secret_key"',
                'site:{} "access_key"',
                'site:{} "private_key"',
                'site:{} "encryption_key"',
                'site:{} "ssh-rsa"',
                'site:{} "BEGIN RSA PRIVATE KEY"',
                'site:{} "BEGIN PRIVATE KEY"',
                'site:{} "aws_access_key_id"',
                'site:{} "AKIA"',
                'site:{} "SKIA"',
                'site:{} "client_secret"',
                'site:{} "app_secret"'
            ],
            'wordpress_specific': [
                'site:{} "wp-content"',
                'site:{} "wp-includes"',
                'site:{} "wp-admin"',
                'site:{} "wp-config.php"',
                'site:{} "wordpress" "user"',
                'site:{} "wordpress" "admin"',
                'site:{} "wp-json"',
                'site:{} "xmlrpc.php"',
                'site:{} "wp-login.php"',
                'site:{} "wp-signup.php"'
            ]
        }

        # GitHub Dork Categories
        self.github_dork_categories = {
            'exposed_secrets': [
                '{} "password"',
                '{} "api_key"',
                '{} "apiKey"',
                '{} "secret"',
                '{} "secret_key"',
                '{} "private_key"',
                '{} "aws_access_key_id"',
                '{} "aws_secret_access_key"',
                '{} "AKIA"',
                '{} "SKIA"',
                '{} "client_secret"',
                '{} "client_id"',
                '{} "access_token"',
                '{} "refresh_token"',
                '{} "bearer_token"',
                '{} "auth_token"',
                '{} "encryption_key"',
                '{} "decryption_key"',
                '{} "crypto_key"',
                '{} "ssh-rsa"',
                '{} "BEGIN RSA PRIVATE KEY"',
                '{} "BEGIN PRIVATE KEY"',
                '{} "BEGIN OPENSSH PRIVATE KEY"',
                '{} "DB_PASSWORD"',
                '{} "DATABASE_URL"',
                '{} "MYSQL_ROOT_PASSWORD"',
                '{} "MONGODB_URI"',
                '{} "REDIS_URL"',
                '{} "MAIL_PASSWORD"',
                '{} "SMTP_PASSWORD"',
                '{} "SENDGRID_API_KEY"',
                '{} "TWILIO_AUTH_TOKEN"',
                '{} "STRIPE_SECRET_KEY"',
                '{} "STRIPE_PUBLISHABLE_KEY"',
                '{} "PAYPAL_CLIENT_SECRET"',
                '{} "FACEBOOK_APP_SECRET"',
                '{} "GOOGLE_CLIENT_SECRET"',
                '{} "GITHUB_TOKEN"',
                '{} "GITLAB_TOKEN"',
                '{} "SLACK_WEBHOOK"',
                '{} "SLACK_TOKEN"',
                '{} "DISCORD_WEBHOOK"',
                '{} "DISCORD_TOKEN"',
                '{} "TELEGRAM_BOT_TOKEN"',
                '{} "JWT_SECRET"',
                '{} "SESSION_SECRET"',
                '{} "ENCRYPTION_SECRET"'
            ],
            'configuration_files': [
                '{} filename:.env',
                '{} filename:config.json',
                '{} filename:config.yml',
                '{} filename:config.yaml',
                '{} filename:settings.py',
                '{} filename:config.py',
                '{} filename:configuration.py',
                '{} filename:secrets.py',
                '{} filename:credentials.py',
                '{} filename:docker-compose.yml',
                '{} filename:docker-compose.yaml',
                '{} filename:dockerfile',
                '{} filename:compose.yml',
                '{} filename:compose.yaml',
                '{} filename:package.json',
                '{} filename:composer.json',
                '{} filename:pom.xml',
                '{} filename:build.gradle',
                '{} filename:build.gradle.kts',
                '{} filename:application.properties',
                '{} filename:application.yml',
                '{} filename:application.yaml'
            ],
            'database_dumps': [
                '{} filename:.sql',
                '{} "dump.sql"',
                '{} "backup.sql"',
                '{} "database.sql"',
                '{} "CREATE TABLE"',
                '{} "INSERT INTO"',
                '{} "DROP TABLE"',
                '{} extension:sql',
                '{} "mysql dump"',
                '{} "pg_dump"',
                '{} "mysqldump"'
            ],
            'log_files': [
                '{} filename:.log',
                '{} "error.log"',
                '{} "debug.log"',
                '{} "access.log"',
                '{} "application.log"',
                '{} extension:log',
                '{} "stack trace"',
                '{} "exception"',
                '{} "DEBUG"',
                '{} "ERROR"'
            ],
            'backup_files': [
                '{} filename:backup',
                '{} "backup.zip"',
                '{} "backup.tar"',
                '{} "backup.rar"',
                '{} "backup.gz"',
                '{} "backup.7z"',
                '{} "database.zip"',
                '{} "dump.zip"',
                '{} "backup_"',
                '{} "_backup"'
            ],
            'api_keys_in_code': [
                '{} "apiKey" extension:js',
                '{} "api_key" extension:py',
                '{} "apikey" extension:java',
                '{} "api-key" extension:php',
                '{} "apisecret" extension:rb',
                '{} "api_secret" extension:go',
                '{} "client_secret" extension:js',
                '{} "client_id" extension:py',
                '{} "accessKey" extension:java',
                '{} "secretKey" extension:php'
            ],
            'hardcoded_credentials': [
                '{} "password ="',
                '{} "username ="',
                '{} "user ="',
                '{} "pass ="',
                '{} "pwd ="',
                '{} "login ="',
                '{} "auth ="',
                '{} "credential"',
                '{} "password:"',
                '{} "username:"',
                '{} "user:"',
                '{} "pass:"'
            ]
        }

    def print_banner(self):
        """Display the tool banner"""
        banner = f"""
{Colors.ORANGE}
╔══════════════════════════════════════════════╗
║               🦥 LAZY DORKER 🦥              ║
║        Advanced Google & GitHub Dorking      ║
║                                              ║
║         Created by Haider (Lazy_Hacks)       ║
║           GitHub: /Lazy-Hacks                ║
╚══════════════════════════════════════════════╝
{Colors.ENDC}"""
        print(banner)

    def random_delay(self, min_seconds=1, max_seconds=15):
        """
        Add random delay between requests to avoid rate limiting
        """
        delay = random.uniform(min_seconds, max_seconds)
        logger.info(f"{Colors.YELLOW}⏳ Random delay: {delay:.2f} seconds{Colors.ENDC}")
        time.sleep(delay)

    # ==================== GOOGLE DORKING METHODS ====================

    def google_search(self, query, num_results=10):
        """Perform Google search and extract results"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            url = f"https://www.google.com/search?q={quote(query)}&num={num_results}"
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return self.parse_google_results(response.text)
            elif response.status_code == 429:
                logger.info(f"{Colors.RED}❌ Rate limited by Google. Increasing delay...{Colors.ENDC}")
                self.random_delay(30, 60)
                return []
            else:
                logger.info(f"{Colors.RED}❌ Google returned status: {response.status_code}{Colors.ENDC}")
                return []
                
        except Exception as e:
            logger.info(f"{Colors.RED}❌ Google search failed: {e}{Colors.ENDC}")
            return []

    def parse_google_results(self, html):
        """Parse Google search results"""
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        for g in soup.find_all('div', class_='g'):
            anchor = g.find('a')
            if anchor and anchor.get('href'):
                link = anchor.get('href')
                title = anchor.get_text()
                
                if link.startswith('/url?q='):
                    link = link.split('/url?q=')[1].split('&')[0]
                    
                if link.startswith('http') and 'google.com' not in link:
                    results.append({
                        'title': title.strip(),
                        'url': link
                    })
        
        return results

    def bing_search(self, query, num_results=10):
        """Alternative search with Bing"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}"
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return self.parse_bing_results(response.text)
            else:
                return []
                
        except Exception as e:
            return []

    def parse_bing_results(self, html):
        """Parse Bing search results"""
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        for li in soup.find_all('li', class_='b_algo'):
            anchor = li.find('a')
            if anchor and anchor.get('href'):
                results.append({
                    'title': anchor.get_text().strip(),
                    'url': anchor.get('href')
                })
        
        return results

    def check_url_content(self, url, dork_category):
        """Check if URL actually contains sensitive content"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents)
            }
            
            response = self.session.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                sensitive_patterns = {
                    'password': ['password', 'pwd', 'passwd', 'senha'],
                    'database': ['database', 'mysql', 'postgresql', 'mongodb'],
                    'config': ['config', 'configuration', 'settings'],
                    'api_key': ['api_key', 'secret_key', 'access_key'],
                    'admin': ['admin', 'administrator', 'wp-admin'],
                    'backup': ['backup', 'dump', 'export'],
                    'login': ['login', 'signin', 'authentication']
                }
                
                found_patterns = []
                for pattern_name, keywords in sensitive_patterns.items():
                    for keyword in keywords:
                        if keyword in content:
                            found_patterns.append(pattern_name)
                            break
                
                if found_patterns:
                    return {
                        'url': url,
                        'category': dork_category,
                        'patterns_found': found_patterns,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    }
            
            return None
            
        except Exception as e:
            return None

    def generate_google_dorks_for_domain(self, domain):
        """Generate all Google dorks for a specific domain"""
        all_dorks = []
        
        for category, dorks in self.google_dork_categories.items():
            for dork in dorks:
                formatted_dork = dork.format(domain)
                all_dorks.append({
                    'dork': formatted_dork,
                    'category': category,
                    'description': self.get_google_dork_description(category),
                    'search_type': 'google'
                })
        
        return all_dorks

    def get_google_dork_description(self, category):
        """Get human-readable description for Google dork category"""
        descriptions = {
            'sensitive_directories': 'Sensitive directories and paths',
            'exposed_config_files': 'Exposed configuration files',
            'database_exposures': 'Database files and management interfaces',
            'backup_files': 'Backup and archive files',
            'log_files': 'Log files with sensitive information',
            'developer_files': 'Developer and version control files',
            'admin_interfaces': 'Administrative interfaces and panels',
            'vulnerable_files': 'Vulnerable and testing files',
            'exposed_documents': 'Exposed documents and spreadsheets',
            'api_endpoints': 'API endpoints and documentation',
            'authentication_pages': 'Authentication and login pages',
            'sensitive_keywords': 'Files containing sensitive keywords',
            'wordpress_specific': 'WordPress-specific files and paths'
        }
        return descriptions.get(category, 'Google search')

    def perform_google_dork_scan(self, domain, max_dorks_per_category=3):
        """Perform comprehensive Google dorking scan"""
        logger.info(f"{Colors.GREEN}🔍 Starting Google dork scan for: {domain}{Colors.ENDC}")
        
        all_dorks = self.generate_google_dorks_for_domain(domain)
        total_dorks = min(len(all_dorks), max_dorks_per_category * len(self.google_dork_categories))
        
        logger.info(f"{Colors.CYAN}📚 Generated {total_dorks} Google dorks across {len(self.google_dork_categories)} categories{Colors.ENDC}")
        
        results = {
            'domain': domain,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {}
        }
        
        for category in self.google_dork_categories.keys():
            category_dorks = [d for d in all_dorks if d['category'] == category][:max_dorks_per_category]
            results['categories'][category] = {
                'dorks_used': [],
                'found_results': []
            }
            
            logger.info(f"{Colors.BLUE}📂 Scanning {category}...{Colors.ENDC}")
            
            for dork_info in category_dorks:
                dork = dork_info['dork']
                results['categories'][category]['dorks_used'].append(dork)
                
                logger.info(f"{Colors.CYAN}   🔎 Dork: {dork}{Colors.ENDC}")
                
                self.random_delay(2, 8)
                
                search_results = []
                google_results = self.google_search(dork)
                search_results.extend(google_results)
                
                if not search_results:
                    bing_results = self.bing_search(dork)
                    search_results.extend(bing_results)
                
                for result in search_results[:5]:
                    content_check = self.check_url_content(result['url'], category)
                    if content_check:
                        results['categories'][category]['found_results'].append(content_check)
                        logger.info(f"{Colors.GREEN}     ✅ Found: {result['url']}{Colors.ENDC}")
        
        return results

    # ==================== GITHUB DORKING METHODS ====================

    def github_search(self, query, max_results=10):
        """Perform GitHub code search using web interface"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            url = f"https://github.com/search?q={quote(query)}&type=code"
            
            logger.info(f"{Colors.CYAN}   🌐 Searching GitHub: {query}{Colors.ENDC}")
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                results = self.parse_github_web_results(response.text, max_results)
                if results:
                    logger.info(f"{Colors.GREEN}     ✅ Found {len(results)} results{Colors.ENDC}")
                else:
                    logger.info(f"{Colors.YELLOW}     ❌ No results found{Colors.ENDC}")
                return results
            elif response.status_code == 429:
                logger.info(f"{Colors.RED}     ⚠️ Rate limited by GitHub. Waiting...{Colors.ENDC}")
                self.random_delay(30, 60)
                return []
            else:
                logger.info(f"{Colors.RED}     ❌ GitHub returned status: {response.status_code}{Colors.ENDC}")
                return []
                
        except Exception as e:
            logger.info(f"{Colors.RED}     ❌ GitHub search failed: {e}{Colors.ENDC}")
            return []

    def parse_github_web_results(self, html, max_results=10):
        """Parse GitHub web search results"""
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        result_items = soup.find_all('div', class_='code-list-item')
        
        for item in result_items[:max_results]:
            try:
                repo_link = item.find('a', class_='Link--secondary')
                file_link = item.find('a', class_='Link--primary')
                
                if repo_link and file_link:
                    repo_name = repo_link.get_text(strip=True)
                    file_name = file_link.get_text(strip=True)
                    file_url = "https://github.com" + file_link.get('href')
                    
                    results.append({
                        'type': 'github',
                        'repository': repo_name,
                        'file_path': file_name,
                        'url': file_url,
                        'description': f"File: {file_name} in {repo_name}"
                    })
            except Exception:
                continue
                
        return results

    def generate_github_dorks_for_target(self, target):
        """Generate GitHub dorks for a specific target"""
        all_dorks = []
        
        for category, dorks in self.github_dork_categories.items():
            for dork in dorks:
                try:
                    formatted_dork = dork.format(target)
                    all_dorks.append({
                        'dork': formatted_dork,
                        'category': f"github_{category}",
                        'description': self.get_github_dork_description(category),
                        'search_type': 'github'
                    })
                except Exception as e:
                    continue
        
        return all_dorks

    def get_github_dork_description(self, category):
        """Get human-readable description for GitHub dork category"""
        descriptions = {
            'exposed_secrets': 'Exposed secrets and API keys',
            'configuration_files': 'Configuration files with secrets',
            'database_dumps': 'Database dumps and SQL files',
            'log_files': 'Log files with sensitive data',
            'backup_files': 'Backup and archive files',
            'api_keys_in_code': 'API keys hardcoded in source code',
            'hardcoded_credentials': 'Hardcoded usernames and passwords'
        }
        return descriptions.get(category, 'GitHub code search')

    def perform_github_dork_scan(self, target, max_dorks_per_category=3):
        """Perform comprehensive GitHub dorking scan"""
        logger.info(f"{Colors.GREEN}🔍 Starting GitHub dork scan for: {target}{Colors.ENDC}")
        
        all_dorks = self.generate_github_dorks_for_target(target)
        total_dorks = min(len(all_dorks), max_dorks_per_category * len(self.github_dork_categories))
        
        logger.info(f"{Colors.CYAN}📚 Generated {total_dorks} GitHub dorks across {len(self.github_dork_categories)} categories{Colors.ENDC}")
        
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {}
        }
        
        for category in self.github_dork_categories.keys():
            github_category = f"github_{category}"
            category_dorks = [d for d in all_dorks if d['category'] == github_category][:max_dorks_per_category]
            results['categories'][github_category] = {
                'dorks_used': [],
                'found_results': []
            }
            
            logger.info(f"{Colors.BLUE}📂 Scanning GitHub {category}...{Colors.ENDC}")
            
            for dork_info in category_dorks:
                dork = dork_info['dork']
                results['categories'][github_category]['dorks_used'].append(dork)
                
                logger.info(f"{Colors.CYAN}   🔎 GitHub Dork: {dork}{Colors.ENDC}")
                
                self.random_delay(3, 8)
                
                github_results = self.github_search(dork)
                
                if github_results:
                    for result in github_results[:5]:
                        enhanced_result = self.check_github_content(result)
                        results['categories'][github_category]['found_results'].append(enhanced_result)
        
        return results

    def check_github_content(self, result):
        """Check if GitHub result actually contains sensitive content"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents)
            }
            
            raw_url = result['url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            
            response = self.session.get(raw_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                
                sensitive_patterns = {
                    'password': ['password', 'pwd', 'passwd'],
                    'api_key': ['api_key', 'apikey', 'api.key'],
                    'secret': ['secret', 'secret_key', 'client_secret'],
                    'token': ['token', 'access_token', 'bearer_token'],
                    'private_key': ['private_key', 'rsa private', 'ssh-rsa'],
                    'database': ['database', 'db_password', 'mysql'],
                    'aws_key': ['aws_access_key_id', 'aws_secret_access_key']
                }
                
                found_patterns = []
                for pattern_name, keywords in sensitive_patterns.items():
                    for keyword in keywords:
                        if keyword.lower() in content.lower():
                            found_patterns.append(pattern_name)
                            break
                
                if found_patterns:
                    result['sensitive_patterns'] = found_patterns
                    result['content_checked'] = True
                    return result
            
            result['content_checked'] = False
            return result
            
        except Exception as e:
            result['content_checked'] = False
            result['error'] = str(e)
            return result

    # ==================== REPORT GENERATION ====================

    def generate_google_report(self, scan_results):
        """Generate Google dorking report"""
        domain = scan_results['domain']
        
        report = f"""
{Colors.PURPLE}
╔══════════════════════════════════════════════╗
║              GOOGLE DORKER REPORT            ║
║                 {scan_results['scan_time']}                 ║
╚══════════════════════════════════════════════╝
{Colors.ENDC}

{Colors.GREEN}🎯 TARGET: {domain}{Colors.ENDC}
{Colors.CYAN}📊 SCAN SUMMARY:{Colors.ENDC}
"""
        
        total_findings = 0
        for category, data in scan_results['categories'].items():
            findings_count = len(data['found_results'])
            total_findings += findings_count
            status_icon = "✅" if findings_count > 0 else "❌"
            report += f"   {status_icon} {category.replace('_', ' ').title()}: {findings_count} findings\n"
        
        report += f"\n{Colors.ORANGE}📈 TOTAL FINDINGS: {total_findings}{Colors.ENDC}\n"
        
        for category, data in scan_results['categories'].items():
            if data['found_results']:
                report += f"\n{Colors.RED}🚨 {category.upper().replace('_', ' ')} FINDINGS:{Colors.ENDC}\n"
                for finding in data['found_results']:
                    report += f"   🔗 URL: {finding['url']}\n"
                    report += f"   📁 Category: {finding['category']}\n"
                    report += f"   🎯 Patterns: {', '.join(finding['patterns_found'])}\n"
                    report += f"   📊 Status: {finding['status_code']}\n"
                    report += "   ──────────────────────\n"
        
        return report

    def generate_combined_report(self, google_results, github_results):
        """Generate comprehensive combined report"""
        target = google_results.get('domain', github_results.get('target', 'Unknown'))
        
        report = f"""
{Colors.PURPLE}
╔══════════════════════════════════════════════╗
║           LAZY DORKER COMBINED REPORT        ║
║                 {google_results.get('scan_time', 'Unknown')}                 ║
╚══════════════════════════════════════════════╝
{Colors.ENDC}

{Colors.GREEN}🎯 TARGET: {target}{Colors.ENDC}
{Colors.CYAN}📊 SCAN SUMMARY:{Colors.ENDC}
"""
        
        google_findings = 0
        for category, data in google_results.get('categories', {}).items():
            findings_count = len(data.get('found_results', []))
            google_findings += findings_count
        
        github_findings = 0
        for category, data in github_results.get('categories', {}).items():
            findings_count = len(data.get('found_results', []))
            github_findings += findings_count
        
        total_findings = google_findings + github_findings
        
        report += f"   🔍 Google Dorking: {google_findings} findings\n"
        report += f"   💻 GitHub Dorking: {github_findings} findings\n"
        report += f"\n{Colors.ORANGE}📈 TOTAL FINDINGS: {total_findings}{Colors.ENDC}\n"
        
        # Google findings
        if google_findings > 0:
            report += f"\n{Colors.RED}🔍 GOOGLE FINDINGS:{Colors.ENDC}\n"
            for category, data in google_results.get('categories', {}).items():
                if data.get('found_results'):
                    for finding in data['found_results'][:3]:
                        report += f"   📁 {category}: {finding['url']}\n"
                        report += f"   🎯 Patterns: {', '.join(finding['patterns_found'])}\n"
                        report += "   ──────────────────────\n"
        
        # GitHub findings
        if github_findings > 0:
            report += f"\n{Colors.RED}💻 GITHUB FINDINGS:{Colors.ENDC}\n"
            for category, data in github_results.get('categories', {}).items():
                if data.get('found_results'):
                    for finding in data['found_results'][:3]:
                        report += f"   📁 {category.replace('github_', '')}: {finding['repository']}\n"
                        report += f"   📄 File: {finding['file_path']}\n"
                        report += f"   🔗 URL: {finding['url']}\n"
                        if finding.get('sensitive_patterns'):
                            report += f"   ⚠️  Sensitive: {', '.join(finding['sensitive_patterns'])}\n"
                        report += "   ──────────────────────\n"
        
        report += f"""
{Colors.ORANGE}
╔══════════════════════════════════════════════╗
║               RECOMMENDATIONS                ║
╚══════════════════════════════════════════════╝{Colors.ENDC}

{Colors.GREEN}🔒 SECURITY ACTIONS:{Colors.ENDC}
   • Remove exposed sensitive files from web servers
   • Scan and remove secrets from GitHub repositories
   • Implement proper access controls
   • Delete unnecessary backup files
   • Rotate exposed API keys and passwords

{Colors.BLUE}📈 NEXT STEPS:{Colors.ENDC}
   • Verify all findings manually
   • Implement security headers
   • Conduct penetration testing
   • Monitor for new exposures regularly

{Colors.PURPLE}
Generated by 🦥 LAZY DORKER v2.1
Complete Google & GitHub Dorking Solution!
Created by Haider (Lazy_Hacks)
{Colors.ENDC}
"""
        return report

    def quick_scan(self, domain):
        """Quick scan with most effective dorks"""
        quick_dorks = [
            f'site:{domain} inurl:"admin"',
            f'site:{domain} inurl:"login"',
            f'site:{domain} inurl:"config"',
            f'site:{domain} filetype:env DB_PASSWORD',
            f'site:{domain} ext:sql "CREATE TABLE"',
            f'site:{domain} inurl:".git"',
            f'site:{domain} "wp-config.php"',
            f'{domain} "password"',
            f'{domain} filename:.env',
            f'{domain} "api_key"'
        ]
        
        logger.info(f"{Colors.GREEN}🚀 Quick scan for: {domain}{Colors.ENDC}")
        
        results = []
        for dork in quick_dorks:
            logger.info(f"{Colors.CYAN}🔍 Checking: {dork}{Colors.ENDC}")
            
            self.random_delay(1, 5)
            
            if 'site:' in dork:
                # Google dork
                search_results = self.google_search(dork)
                for result in search_results[:2]:
                    results.append({
                        'dork': dork,
                        'url': result['url'],
                        'title': result['title'],
                        'type': 'google'
                    })
                    logger.info(f"{Colors.GREEN}   ✅ Found: {result['url']}{Colors.ENDC}")
            else:
                # GitHub dork
                github_results = self.github_search(dork)
                for result in github_results[:2]:
                    results.append({
                        'dork': dork,
                        'url': result['url'],
                        'title': result['description'],
                        'type': 'github'
                    })
                    logger.info(f"{Colors.GREEN}   ✅ Found: {result['description']}{Colors.ENDC}")
        
        return results

def main():
    """Main function to run LAZY DORKER"""
    parser = argparse.ArgumentParser(
        description='LAZY DORKER - Advanced Google & GitHub Dorking Tool for Security Researchers',
        epilog='''
Examples:
  python3 lazy_dorker.py -d example.com              # Google dorking only
  python3 lazy_dorker.py -d example.com --github     # GitHub dorking only  
  python3 lazy_dorker.py -d example.com --combined   # Combined scan
  python3 lazy_dorker.py -d example.com --quick      # Quick scan
        '''
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-q', '--quick', action='store_true', help='Perform quick scan (mixed Google & GitHub dorks)')
    parser.add_argument('-g', '--github', action='store_true', help='Perform GitHub dorking only')
    parser.add_argument('-c', '--combined', action='store_true', help='Perform combined Google and GitHub dorking')
    parser.add_argument('-o', '--output', help='Save report to custom filename')
    parser.add_argument('--max-dorks', type=int, default=3, help='Max dorks per category (default: 3)')
    parser.add_argument('--min-delay', type=float, default=1, help='Minimum delay between dorks (default: 1)')
    parser.add_argument('--max-delay', type=float, default=15, help='Maximum delay between dorks (default: 15)')
    
    args = parser.parse_args()
    
    # Create outputs directory
    os.makedirs('dork_results', exist_ok=True)
    
    # Initialize tool
    tool = LazyDorker()
    tool.print_banner()
    
    logger.info(f"{Colors.GREEN}🎯 Target: {args.domain}{Colors.ENDC}")
    logger.info(f"{Colors.YELLOW}⚠️  Educational use only - Respect robots.txt and terms of service{Colors.ENDC}")
    logger.info(f"{Colors.CYAN}⏰ Delay range: {args.min_delay}-{args.max_delay} seconds between dorks{Colors.ENDC}")
    
    if args.quick:
        # Quick scan (mixed Google & GitHub)
        results = tool.quick_scan(args.domain)
        
        print(f"\n{Colors.GREEN}🚀 QUICK SCAN RESULTS:{Colors.ENDC}")
        for result in results:
            icon = "🔍" if result['type'] == 'google' else "💻"
            print(f"   {icon} {result['url']}")
            print(f"   📝 {result['title']}")
            print(f"   🔎 Dork: {result['dork']}")
            print("   ──────────────────────")
            
    elif args.github:
        # GitHub dorking only
        github_results = tool.perform_github_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_combined_report({}, github_results)
        print(report)
        
    elif args.combined:
        # Combined Google and GitHub dorking
        logger.info(f"{Colors.GREEN}🔄 Starting combined Google & GitHub scan...{Colors.ENDC}")
        google_results = tool.perform_google_dork_scan(args.domain, args.max_dorks)
        github_results = tool.perform_github_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_combined_report(google_results, github_results)
        print(report)
        
    else:
        # Default: Google dorking only
        google_results = tool.perform_google_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_google_report(google_results)
        print(report)
    
    # Save report for all modes except quick scan
    if not args.quick:
        if args.output:
            report_filename = f"dork_results/{args.output}"
        else:
            timestamp = int(time.time())
            if args.github:
                scan_type = "github"
            elif args.combined:
                scan_type = "combined"
            else:
                scan_type = "google"
            report_filename = f"dork_results/{scan_type}_scan_{args.domain}_{timestamp}.txt"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            clean_report = re.sub(r'\033\[[0-9;]*m', '', report)
            f.write(clean_report)
        
        logger.info(f"{Colors.GREEN}💾 Report saved: {report_filename}{Colors.ENDC}")
    
    logger.info(f"{Colors.GREEN}✅ LAZY DORKER completed!{Colors.ENDC}")


if __name__ == "__main__":
    main()
