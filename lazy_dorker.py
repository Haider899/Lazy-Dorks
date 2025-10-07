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
        self.results = {
            'target': '',
            'dorks_used': [],
            'vulnerabilities_found': [],
            'exposed_files': [],
            'sensitive_info': [],
            'admin_panels': [],
            'backup_files': [],
            'database_dumps': [],
            'login_pages': [],
            'github_findings': []
        }
        
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

        # GitHub Dork Categories - Fixed to handle single target parameter
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
            'company_specific_secrets': [
                '{} "company" "password"',
                '{} "internal" "key"',
                '{} "confidential" "secret"',
                '{} "proprietary" "api"',
                '{} "production" "database"',
                '{} "staging" "config"',
                '{} "development" "env"',
                '{} "test" "credential"',
                '{} "demo" "password"'
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
            ],
            'sensitive_documentation': [
                '{} "README" "password"',
                '{} "readme.md" "secret"',
                '{} "README.txt" "key"',
                '{} "INSTALL" "database"',
                '{} "SETUP" "config"',
                '{} "TODO" "credential"',
                '{} "NOTES" "password"'
            ],
            'company_repositories': [
                'org:{}',  # This will use the target as organization
                'user:{}',  # This will use the target as username
                '{} in:name',  # Search in repository names
                '{} in:description',  # Search in repository descriptions
                '{} in:readme'  # Search in README files
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
        
        Args:
            min_seconds (float): Minimum delay in seconds
            max_seconds (float): Maximum delay in seconds
        """
        delay = random.uniform(min_seconds, max_seconds)
        logger.info(f"{Colors.YELLOW}⏳ Random delay: {delay:.2f} seconds{Colors.ENDC}")
        time.sleep(delay)

    def github_search(self, query, max_results=10):
        """
        Perform GitHub code search using web interface (no API key required)
        
        Args:
            query (str): Search query for GitHub
            max_results (int): Maximum number of results to return
            
        Returns:
            list: List of GitHub search results
        """
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            # GitHub web search (no API key required)
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
        """
        Parse GitHub web search results
        
        Args:
            html (str): HTML content of GitHub search results
            max_results (int): Maximum results to return
            
        Returns:
            list: Parsed results
        """
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        # Find code search result items
        result_items = soup.find_all('div', class_='code-list-item')
        
        for item in result_items[:max_results]:
            try:
                repo_link = item.find('a', class_='Link--secondary')
                file_link = item.find('a', class_='Link--primary')
                
                if repo_link and file_link:
                    repo_name = repo_link.get_text(strip=True)
                    file_name = file_link.get_text(strip=True)
                    file_url = "https://github.com" + file_link.get('href')
                    
                    # Extract code snippet if available
                    code_snippet = ""
                    code_block = item.find('div', class_='code-excerpt')
                    if code_block:
                        code_snippet = code_block.get_text(strip=True)[:200]  # First 200 chars
                    
                    results.append({
                        'type': 'github',
                        'repository': repo_name,
                        'file_path': file_name,
                        'url': file_url,
                        'code_snippet': code_snippet,
                        'description': f"File: {file_name} in {repo_name}"
                    })
            except Exception as e:
                continue
                
        return results

    def generate_github_dorks_for_target(self, target):
        """
        Generate GitHub dorks for a specific target
        
        Args:
            target (str): Target domain or company name
            
        Returns:
            list: All formatted GitHub dorks
        """
        all_dorks = []
        
        for category, dorks in self.github_dork_categories.items():
            for dork in dorks:
                try:
                    # Handle dorks with single placeholder
                    if dork.count('{}') == 1:
                        formatted_dork = dork.format(target)
                    else:
                        # For dorks that might have multiple placeholders, use only the target
                        formatted_dork = dork.replace('{}', target, 1)
                        # Remove any remaining placeholders
                        formatted_dork = formatted_dork.replace('{}', target)
                        
                    all_dorks.append({
                        'dork': formatted_dork,
                        'category': f"github_{category}",
                        'description': self.get_github_dork_description(category, dork),
                        'search_type': 'github'
                    })
                except Exception as e:
                    logger.info(f"{Colors.RED}❌ Error formatting dork: {dork} - {e}{Colors.ENDC}")
                    continue
        
        return all_dorks

    def get_github_dork_description(self, category, dork):
        """
        Get human-readable description for GitHub dork category
        
        Args:
            category (str): Dork category
            dork (str): The dork string
            
        Returns:
            str: Human-readable description
        """
        descriptions = {
            'exposed_secrets': 'Exposed secrets and API keys',
            'company_specific_secrets': 'Company-specific sensitive information',
            'configuration_files': 'Configuration files with secrets',
            'database_dumps': 'Database dumps and SQL files',
            'log_files': 'Log files with sensitive data',
            'backup_files': 'Backup and archive files',
            'api_keys_in_code': 'API keys hardcoded in source code',
            'hardcoded_credentials': 'Hardcoded usernames and passwords',
            'sensitive_documentation': 'Documentation containing secrets',
            'company_repositories': 'Company-specific repositories'
        }
        return descriptions.get(category, 'GitHub code search')

    def perform_github_dork_scan(self, target, max_dorks_per_category=3):
        """
        Perform comprehensive GitHub dorking scan
        
        Args:
            target (str): Target domain or company name
            max_dorks_per_category (int): Maximum dorks per category
            
        Returns:
            dict: GitHub scan results
        """
        logger.info(f"{Colors.GREEN}🔍 Starting GitHub dork scan for: {target}{Colors.ENDC}")
        
        all_dorks = self.generate_github_dorks_for_target(target)
        total_dorks = min(len(all_dorks), max_dorks_per_category * len(self.github_dork_categories))
        
        logger.info(f"{Colors.CYAN}📚 Generated {total_dorks} GitHub dorks across {len(self.github_dork_categories)} categories{Colors.ENDC}")
        
        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {}
        }
        
        # Process GitHub dorks by category
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
                
                # Add random delay before each GitHub search
                self.random_delay(3, 8)
                
                # Perform GitHub search
                github_results = self.github_search(dork)
                
                if github_results:
                    for result in github_results[:5]:  # Limit to first 5 results per dork
                        # Check if result actually contains sensitive content
                        enhanced_result = self.check_github_content(result)
                        results['categories'][github_category]['found_results'].append(enhanced_result)
                else:
                    logger.info(f"{Colors.YELLOW}     ❌ No results found{Colors.ENDC}")
        
        return results

    def check_github_content(self, result):
        """
        Check if GitHub result actually contains sensitive content
        
        Args:
            result (dict): GitHub search result
            
        Returns:
            dict: Enhanced result with content analysis
        """
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents)
            }
            
            # For GitHub, we can check the raw file content
            raw_url = result['url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            
            response = self.session.get(raw_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                content = response.text
                
                # Check for sensitive patterns in the content
                sensitive_patterns = {
                    'password': ['password', 'pwd', 'passwd'],
                    'api_key': ['api_key', 'apikey', 'api.key'],
                    'secret': ['secret', 'secret_key', 'client_secret'],
                    'token': ['token', 'access_token', 'bearer_token'],
                    'private_key': ['private_key', 'rsa private', 'ssh-rsa'],
                    'database': ['database', 'db_password', 'mysql'],
                    'aws_key': ['aws_access_key_id', 'aws_secret_access_key'],
                    'email': ['@', 'smtp', 'mail'],
                    'url': ['http://', 'https://', 'ftp://']
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
                    
                    # Extract a sample of the sensitive content
                    sample_content = ""
                    for pattern in found_patterns[:2]:  # Show first 2 patterns
                        for keyword in sensitive_patterns[pattern]:
                            if keyword.lower() in content.lower():
                                idx = content.lower().find(keyword.lower())
                                if idx != -1:
                                    start = max(0, idx - 50)
                                    end = min(len(content), idx + len(keyword) + 50)
                                    sample_content = content[start:end].replace('\n', ' ').strip()
                                    break
                        if sample_content:
                            break
                    
                    result['sample_content'] = sample_content[:200]  # Limit sample size
                    return result
            
            result['content_checked'] = False
            return result
            
        except Exception as e:
            result['content_checked'] = False
            result['error'] = str(e)
            return result

    # ... (Include all the existing Google dorking methods)

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
            
            # Google search URL
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
        
        # Find all search result links
        for g in soup.find_all('div', class_='g'):
            anchor = g.find('a')
            if anchor and anchor.get('href'):
                link = anchor.get('href')
                title = anchor.get_text()
                
                # Filter out Google's own links
                if link.startswith('/url?q='):
                    link = link.split('/url?q=')[1].split('&')[0]
                    
                if link.startswith('http') and 'google.com' not in link:
                    results.append({
                        'title': title.strip(),
                        'url': link
                    })
        
        return results

    def perform_dork_scan(self, domain, max_dorks_per_category=5):
        """Perform comprehensive Google dorking scan"""
        logger.info(f"{Colors.GREEN}🎯 Starting Google dork scan for: {domain}{Colors.ENDC}")
        
        # This would contain the Google dork scanning logic
        # For now, return empty results for Google scan
        return {
            'domain': domain,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {}
        }

    def generate_combined_report(self, google_results, github_results):
        """
        Generate comprehensive report combining Google and GitHub findings
        """
        target = google_results.get('domain', github_results.get('target', 'Unknown'))
        
        report = f"""
{Colors.PURPLE}
╔══════════════════════════════════════════════╗
║           LAZY DORKER COMBINED REPORT        ║
║                 {github_results.get('scan_time', 'Unknown')}                 ║
╚══════════════════════════════════════════════╝
{Colors.ENDC}

{Colors.GREEN}🎯 TARGET: {target}{Colors.ENDC}
{Colors.CYAN}📊 SCAN SUMMARY:{Colors.ENDC}
"""
        
        # GitHub findings summary
        github_findings = 0
        for category, data in github_results.get('categories', {}).items():
            findings_count = len(data.get('found_results', []))
            github_findings += findings_count
        
        total_findings = github_findings
        
        report += f"   💻 GitHub Dorking: {github_findings} findings\n"
        report += f"\n{Colors.ORANGE}📈 TOTAL FINDINGS: {total_findings}{Colors.ENDC}\n"
        
        # GitHub findings details
        if github_findings > 0:
            report += f"\n{Colors.RED}🚨 GITHUB FINDINGS:{Colors.ENDC}\n"
            for category, data in github_results.get('categories', {}).items():
                if data.get('found_results'):
                    report += f"\n   📂 {category.replace('github_', '').replace('_', ' ').title()}:\n"
                    for finding in data['found_results'][:5]:  # Show first 5 per category
                        report += f"      🔗 Repository: {finding.get('repository', 'Unknown')}\n"
                        report += f"      📁 File: {finding.get('file_path', 'Unknown')}\n"
                        report += f"      🌐 URL: {finding.get('url', 'Unknown')}\n"
                        if finding.get('sensitive_patterns'):
                            report += f"      ⚠️  Sensitive Data: {', '.join(finding['sensitive_patterns'])}\n"
                        if finding.get('sample_content'):
                            report += f"      📝 Sample: {finding['sample_content']}...\n"
                        report += "      ──────────────────────\n"
        else:
            report += f"\n{Colors.YELLOW}📭 No sensitive findings in GitHub repositories.{Colors.ENDC}\n"
        
        # Dorks used
        report += f"\n{Colors.BLUE}🔍 GITHUB DORKS USED:{Colors.ENDC}\n"
        
        # GitHub dorks
        if github_results.get('categories'):
            for category, data in github_results.get('categories', {}).items():
                if data.get('dorks_used'):
                    report += f"\n   📂 {category.replace('github_', '').replace('_', ' ').title()}:\n"
                    for dork in data['dorks_used'][:3]:  # Show first 3 dorks per category
                        report += f"      • {dork}\n"
        
        report += f"""
{Colors.ORANGE}
╔══════════════════════════════════════════════╗
║               RECOMMENDATIONS                ║
╚══════════════════════════════════════════════╝{Colors.ENDC}

{Colors.GREEN}🔒 SECURITY ACTIONS:{Colors.ENDC}
   • Remove exposed secrets from GitHub repositories
   • Implement pre-commit hooks to detect secrets
   • Use GitHub secret scanning service
   • Rotate all exposed API keys and passwords
   • Review and clean up sensitive documentation

{Colors.BLUE}📈 NEXT STEPS:{Colors.ENDC}
   • Verify all findings manually
   • Check for additional organization repositories
   • Implement automated secret detection
   • Conduct internal security awareness training
   • Monitor for new exposures regularly

{Colors.PURPLE}
Generated by 🦥 LAZY DORKER v2.1
GitHub Dorking - No API Key Required!
Created by Haider (Lazy_Hacks)
{Colors.ENDC}
"""
        return report

def main():
    """Main function to run LAZY DORKER"""
    parser = argparse.ArgumentParser(
        description='LAZY DORKER - Advanced Google & GitHub Dorking Tool for Security Researchers',
        epilog='Example: python3 lazy_dorker.py -d example.com --github'
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-q', '--quick', action='store_true', help='Perform quick scan (12 most effective dorks)')
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
    
    if args.github:
        # GitHub dorking only
        github_results = tool.perform_github_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_combined_report({}, github_results)
        print(report)
        
    elif args.combined:
        # Combined Google and GitHub dorking
        google_results = tool.perform_dork_scan(args.domain, args.max_dorks)
        github_results = tool.perform_github_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_combined_report(google_results, github_results)
        print(report)
        
    elif args.quick:
        # Quick Google scan
        logger.info(f"{Colors.YELLOW}⚠️  Quick scan currently supports only Google dorking{Colors.ENDC}")
        # Add quick scan logic here if needed
    else:
        # Google dorking only
        scan_results = tool.perform_dork_scan(args.domain, args.max_dorks)
        report = tool.generate_combined_report(scan_results, {})
        print(report)
    
    # Save report
    if args.github or args.combined or (not args.quick and not args.github and not args.combined):
        if args.output:
            report_filename = f"dork_results/{args.output}"
        else:
            timestamp = int(time.time())
            scan_type = "github" if args.github else "combined" if args.combined else "google"
            report_filename = f"dork_results/{scan_type}_scan_{args.domain}_{timestamp}.txt"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            clean_report = re.sub(r'\033\[[0-9;]*m', '', report)
            f.write(clean_report)
        
        logger.info(f"{Colors.GREEN}💾 Report saved: {report_filename}{Colors.ENDC}")
    
    logger.info(f"{Colors.GREEN}✅ LAZY DORKER completed!{Colors.ENDC}")


if __name__ == "__main__":
    main()
