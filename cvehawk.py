"""
CVEHawk - Advanced CVE Lookup Tool v2.1
A multi-threaded command-line tool for CVE information gathering
Enhanced with better POC search and multi-platform support
"""

import argparse
import requests
import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import re
from urllib.parse import quote, urlencode
import os
from datetime import datetime
import tempfile
import csv
from pathlib import Path
import html
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. Configuration files not supported.")
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class RateLimiter:
    """Handle API rate limiting with automatic cooldown and resume"""
    def __init__(self):
        self.github_requests = 0
        self.github_reset_time = None
        self.github_limit = 60  # Default for unauthenticated
        self.github_remaining = 60
        self.nvd_last_request = time.time()
        self.nvd_min_interval = 0.6  # Minimum seconds between NVD requests
        
    def check_github_limit(self, headers):
        """Update GitHub rate limit info from response headers"""
        if 'X-RateLimit-Limit' in headers:
            self.github_limit = int(headers['X-RateLimit-Limit'])
        if 'X-RateLimit-Remaining' in headers:
            self.github_remaining = int(headers['X-RateLimit-Remaining'])
        if 'X-RateLimit-Reset' in headers:
            self.github_reset_time = int(headers['X-RateLimit-Reset'])
            
    def wait_if_needed(self, api_type='github'):
        """Wait if rate limit is close or exceeded"""
        if api_type == 'github':
            if self.github_remaining <= 2 and self.github_reset_time:
                wait_time = self.github_reset_time - time.time()
                if wait_time > 0:
                    print(f"{Colors.YELLOW}[RATE LIMIT]{Colors.RESET} GitHub API limit reached. Cooling down for {wait_time:.0f} seconds...")
                    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Will resume automatically after cooldown period.")
                    for i in range(int(wait_time)):
                        time.sleep(1)
                        remaining = int(wait_time - i - 1)
                        if remaining % 10 == 0 and remaining > 0:
                            print(f"{Colors.YELLOW}[COOLDOWN]{Colors.RESET} {remaining} seconds remaining...")
                    
                    print(f"{Colors.GREEN}[RESUMED]{Colors.RESET} Continuing with API requests...")
                    self.github_remaining = self.github_limit  # Reset after cooldown
                    return True
        elif api_type == 'nvd':
            elapsed = time.time() - self.nvd_last_request
            if elapsed < self.nvd_min_interval:
                time.sleep(self.nvd_min_interval - elapsed)
            self.nvd_last_request = time.time()
        return False

def print_banner():
    """Enhanced ASCII art banner with better visual appeal"""
    banner = f"""{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║  ██████╗██╗   ██╗███████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗      ║
║ ██╔════╝██║   ██║██╔════╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝      ║
║ ██║     ██║   ██║█████╗  ███████║███████║██║ █╗ ██║█████╔╝       ║
║ ██║     ╚██╗ ██╔╝██╔══╝  ██╔══██║██╔══██║██║███╗██║██╔═██╗       ║
║ ╚██████╗ ╚████╔╝ ███████╗██║  ██║██║  ██║╚███╔███╔╝██║  ██╗      ║
║  ╚═════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝      ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}               Advanced CVE Lookup Tool v2.1 Enhanced{Colors.RESET}
{Colors.MAGENTA}                        Created by @alsh4rfi{Colors.RESET}
{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
{Colors.GREEN} Enhanced Features: Multi-Platform POC Search | Smart Ranking | Export+{Colors.RESET}
"""
    print(banner)

class CVELookup:
    def __init__(self, config_file: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVEHawk/2.1 (Security Research Tool)',
            'Accept': 'application/json'
        })
        self.lock = threading.Lock()
        self.config = self.load_config(config_file)
        self.rate_limiter = RateLimiter()  # Add rate limiter
        self.mitre_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.github_api = "https://api.github.com/search/repositories"
        self.github_code_api = "https://api.github.com/search/code"
        self.epss_api = "https://api.first.org/data/v1/epss"
        self.exploit_db_search = "https://www.exploit-db.com/search"
        self.packetstorm_search = "https://packetstormsecurity.com/search"
        if self.config.get('api_keys', {}).get('github'):
            self.session.headers['Authorization'] = f"token {self.config['api_keys']['github']}"
            self.rate_limiter.github_limit = 5000  # Authenticated limit
            self.rate_limiter.github_remaining = 5000
        else:
            self.rate_limiter.github_limit = 60
            self.rate_limiter.github_remaining = 60

    def display_rate_limit_status(self):
        """Display current rate limit status"""
        print(f"\n{Colors.BOLD}API Rate Limit Status:{Colors.RESET}")
        print(f"  • GitHub: {Colors.CYAN}{self.rate_limiter.github_remaining}/{self.rate_limiter.github_limit}{Colors.RESET} requests remaining")
        
        if self.rate_limiter.github_reset_time:
            reset_in = self.rate_limiter.github_reset_time - time.time()
            if reset_in > 0:
                print(f"  • Reset in: {Colors.YELLOW}{reset_in/60:.1f} minutes{Colors.RESET}")
        
        if self.rate_limiter.github_remaining < 10:
            print(f"  {Colors.YELLOW}⚠ Warning: Running low on API requests. Consider adding a GitHub token.{Colors.RESET}")
    
    def load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from YAML file"""
        default_config = {
            'api_keys': {},
            'output': {
                'format': 'detailed',
                'colors': True
            },
            'filters': {
                'min_severity': 'none'
            },
            'export': {
                'directory': './cvehawk_reports'
            }
        }
        
        if config_file and os.path.exists(config_file) and YAML_AVAILABLE:
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                    default_config.update(user_config)
            except Exception as e:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Error loading config: {e}")
                
        return default_config

    def get_severity_color(self, severity: str) -> str:
        """Get color based on CVSS severity"""
        severity = severity.upper()
        colors = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'NONE': Colors.BLUE,
            'UNKNOWN': Colors.WHITE
        }
        return colors.get(severity, Colors.WHITE)

    def normalize_cve_id(self, cve_id: str) -> str:
        """Normalize CVE ID by replacing various dash characters with standard hyphen"""
        normalized = cve_id.replace('–', '-').replace('—', '-').replace('−', '-')
        return normalized.upper().strip()

    def validate_cve_format(self, cve_id: str) -> bool:
        """Validate CVE ID format"""
        normalized = self.normalize_cve_id(cve_id)
        pattern = r'^CVE-\d{4}-\d{4,7}$'
        return bool(re.match(pattern, normalized))

    def fetch_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE details from NVD API"""
        try:
            self.rate_limiter.wait_if_needed('nvd')
            normalized_cve = self.normalize_cve_id(cve_id)
            
            if not self.validate_cve_format(normalized_cve):
                raise ValueError(f"Invalid CVE format: {cve_id} (normalized: {normalized_cve})")
                
            url = f"{self.mitre_api}?cveId={normalized_cve}"
            
            with self.lock:
                print(f"{Colors.BLUE}[INFO]{Colors.RESET} Fetching data for {normalized_cve}...")
                
            response = self.session.get(url, timeout=30)
            if response.status_code == 404:
                with self.lock:
                    print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} CVE {normalized_cve} not found in NVD database")
                    print(f"{Colors.YELLOW}[INFO]{Colors.RESET} This could be because:")
                    print(f"  • The CVE is very recent and not yet published")
                    print(f"  • The CVE is from a future year")
                    print(f"  • The CVE ID doesn't exist")
                return None
            elif response.status_code == 403:
                with self.lock:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Access denied (403) - API rate limit or authentication issue")
                return None
                
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                with self.lock:
                    print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No results found for {normalized_cve}")
                    print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Trying alternative search methods...")
                return self.try_alternative_search(normalized_cve)
                
            return data['vulnerabilities'][0]['cve']
            
        except requests.exceptions.RequestException as e:
            with self.lock:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Network error for {normalized_cve}: {e}")
            return None
        except ValueError as e:
            with self.lock:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} {e}")
            return None
        except Exception as e:
            with self.lock:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error for {normalized_cve}: {e}")
            return None

    def try_alternative_search(self, cve_id: str) -> Optional[Dict]:
        """Try alternative search methods when primary lookup fails"""
        try:
            alt_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            
            with self.lock:
                print(f"{Colors.BLUE}[INFO]{Colors.RESET} Trying alternative API for {cve_id}...")
                
            response = self.session.get(alt_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if 'result' in data and 'CVE_Items' in data['result']:
                    cve_items = data['result']['CVE_Items']
                    if cve_items:
                        old_cve = cve_items[0]['cve']
                        return self.convert_old_format_to_new(old_cve)
            
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {cve_id} not found in any available database")
                
        except Exception as e:
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Alternative search failed for {cve_id}: {e}")
                
        return None

    def convert_old_format_to_new(self, old_cve_data: Dict) -> Dict:
        """Convert old API format to new format for compatibility"""
        try:
            converted = {
                'id': old_cve_data.get('CVE_data_meta', {}).get('ID', ''),
                'descriptions': [],
                'published': old_cve_data.get('publishedDate', ''),
                'lastModified': old_cve_data.get('lastModifiedDate', ''),
                'references': [],
                'metrics': {}
            }
            if 'description' in old_cve_data:
                for desc in old_cve_data['description']['description_data']:
                    converted['descriptions'].append({
                        'lang': desc.get('lang', 'en'),
                        'value': desc.get('value', '')
                    })
            if 'references' in old_cve_data:
                for ref in old_cve_data['references']['reference_data']:
                    converted['references'].append({
                        'url': ref.get('url', ''),
                        'tags': ref.get('tags', [])
                    })
                    
            return converted
            
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Error converting old format: {e}")
            return old_cve_data

    def fetch_epss_score(self, cve_id: str) -> Optional[Dict]:
        """Fetch EPSS (Exploit Prediction Scoring System) data"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            url = f"{self.epss_api}?cve={normalized_cve}"
            
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == 'OK' and data.get('data'):
                epss_data = data['data'][0]
                return {
                    'epss_score': float(epss_data.get('epss', 0)),
                    'epss_percentile': float(epss_data.get('percentile', 0)),
                    'date': epss_data.get('date', '')
                }
                
        except Exception as e:
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} EPSS lookup failed for {cve_id}: {e}")
                
        return None

    def search_github_repositories(self, cve_id: str) -> List[Dict]:
        """Enhanced GitHub repository search with rate limiting"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            cve_parts = normalized_cve.split('-')
            cve_year = cve_parts[1] if len(cve_parts) > 1 else ""
            cve_number = cve_parts[2] if len(cve_parts) > 2 else ""
            search_queries = [
                f'"{normalized_cve}" AND (exploit OR poc OR "proof of concept")',
                f'"{normalized_cve}" vulnerability',
                f'"CVE-{cve_year}-{cve_number}" exploit',
                f'CVE {cve_year} {cve_number} exploit',
                f'{normalized_cve} language:python exploit',
                f'{normalized_cve} language:c exploit',
                f'intitle:"{normalized_cve}" exploit',
            ]
            
            all_results = []
            seen_urls = set()
            
            for i, query in enumerate(search_queries[:7]):
                try:
                    self.rate_limiter.wait_if_needed('github')
                    
                    sort_strategies = ["stars", "updated", "best-match", "forks"]
                    sort_param = sort_strategies[i % len(sort_strategies)]
                        
                    url = f"{self.github_api}?q={quote(query)}&sort={sort_param}&order=desc&per_page=20"
                    
                    response = self.session.get(url, timeout=25)
                    self.rate_limiter.check_github_limit(response.headers)
                    
                    if response.status_code == 403:
                        rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                        if rate_limit_reset:
                            wait_time = int(rate_limit_reset) - time.time()
                            if wait_time > 0:
                                with self.lock:
                                    print(f"{Colors.YELLOW}[RATE LIMIT]{Colors.RESET} GitHub API limit hit. Auto-cooling down for {wait_time:.0f}s...")
                                for countdown in range(int(wait_time), 0, -1):
                                    if countdown % 30 == 0:
                                        print(f"{Colors.BLUE}[COOLDOWN]{Colors.RESET} {countdown} seconds remaining...")
                                    time.sleep(1)
                                
                                print(f"{Colors.GREEN}[RESUMED]{Colors.RESET} Retrying request...")
                                response = self.session.get(url, timeout=25)
                                if response.status_code == 403:
                                    break  # Still limited, stop trying
                        else:
                            with self.lock:
                                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GitHub API rate limited. Consider adding API key.")
                            break
                            
                    elif response.status_code == 422:
                        continue
                        
                    if response.status_code != 200:
                        continue
                        
                    data = response.json()
                    for item in data.get('items', [])[:15]:
                        repo_url = item.get('html_url', '')
                        if repo_url and repo_url not in seen_urls:
                            seen_urls.add(repo_url)
                            
                            if self.is_likely_poc_enhanced(item, normalized_cve):
                                try:
                                    created = item.get('created_at', '')
                                    pushed = item.get('pushed_at', '')
                                    if created and pushed:
                                        from datetime import datetime
                                        created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                                        pushed_date = datetime.fromisoformat(pushed.replace('Z', '+00:00'))
                                        days_active = (pushed_date - created_date).days
                                        item['estimated_commits'] = max(1, min(days_active * 7, 10000))
                                    else:
                                        item['estimated_commits'] = item.get('size', 0) // 10
                                except:
                                    item['estimated_commits'] = 0
                                    
                                item['search_query'] = query
                                item['search_rank'] = i
                                item['relevance_score'] = self.calculate_relevance_score(item, normalized_cve)
                                all_results.append(item)
                    if self.rate_limiter.github_remaining > 30:
                        time.sleep(0.2)  # Fast when we have quota
                    elif self.rate_limiter.github_remaining > 10:
                        time.sleep(0.5)  # Slower when getting low
                    else:
                        time.sleep(1.0)  # Very slow when almost out
                        
                except requests.exceptions.RequestException:
                    continue
            all_results.sort(key=lambda x: (
                x.get('stargazers_count', 0) * 1000 +
                x.get('forks_count', 0) * 100 +
                x.get('estimated_commits', 0) * 0.1
            ), reverse=True)
            with self.lock:
                if all_results:
                    print(f"{Colors.GREEN}[INFO]{Colors.RESET} Found {len(all_results)} POCs (GitHub API: {self.rate_limiter.github_remaining}/{self.rate_limiter.github_limit} requests remaining)")
            
            return all_results[:15]
                
        except Exception as e:
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GitHub repository search error: {e}")
            return []
    
    def search_github_code(self, cve_id: str) -> List[Dict]:
        """Search for code mentioning the CVE with rate limiting"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            
            search_queries = [
                f'"{normalized_cve}" exploit',
                f'"{normalized_cve}" poc',
                f'"{normalized_cve}" vulnerability'
            ]
            
            all_results = []
            seen_repos = set()
            
            for query in search_queries[:2]:
                try:
                    self.rate_limiter.wait_if_needed('github')
                    
                    url = f"{self.github_code_api}?q={quote(query)}&sort=indexed&per_page=10"
                    
                    response = self.session.get(url, timeout=15)
                    self.rate_limiter.check_github_limit(response.headers)
                    
                    if response.status_code == 403:
                        rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                        if rate_limit_reset:
                            wait_time = int(rate_limit_reset) - time.time()
                            if wait_time > 0 and wait_time < 300:  # Wait up to 5 minutes
                                with self.lock:
                                    print(f"{Colors.YELLOW}[RATE LIMIT]{Colors.RESET} Code search limit hit. Cooling down...")
                                time.sleep(wait_time + 1)
                                response = self.session.get(url, timeout=15)
                                if response.status_code == 403:
                                    break
                        else:
                            break
                    elif response.status_code != 200:
                        continue
                        
                    data = response.json()
                    
                    for item in data.get('items', [])[:5]:
                        repo = item.get('repository', {})
                        repo_url = repo.get('html_url', '')
                        
                        if repo_url and repo_url not in seen_repos:
                            seen_repos.add(repo_url)
                            
                            repo_item = {
                                'html_url': repo_url,
                                'full_name': repo.get('full_name', ''),
                                'description': repo.get('description', ''),
                                'stargazers_count': repo.get('stargazers_count', 0),
                                'forks_count': repo.get('forks_count', 0),
                                'language': repo.get('language', ''),
                                'updated_at': repo.get('updated_at', ''),
                                'size': repo.get('size', 0),
                                'open_issues_count': repo.get('open_issues_count', 0),
                                'source': 'github_code_search',
                                'code_file': item.get('name', ''),
                                'code_path': item.get('path', ''),
                                'relevance_score': self.calculate_relevance_score(repo, normalized_cve)
                            }
                            
                            all_results.append(repo_item)
                    if self.rate_limiter.github_remaining > 10:
                        time.sleep(0.3)
                    else:
                        time.sleep(1.0)
                        
                except requests.exceptions.RequestException:
                    continue
                        
            return all_results
                
        except Exception as e:
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GitHub code search error: {e}")
            return []

    def is_likely_poc_enhanced(self, repo: Dict, cve_id: str) -> bool:
        """Enhanced POC detection with better filtering and regex matching"""
        repo_name = repo.get('full_name', '').lower()
        description = (repo.get('description') or '').lower()
        cve_lower = cve_id.lower()
        cve_parts = cve_lower.split('-')
        cve_year = cve_parts[1] if len(cve_parts) > 1 else ""
        cve_number = cve_parts[2] if len(cve_parts) > 2 else ""
        cve_patterns = [
            cve_lower,  # Exact match
            cve_lower.replace('-', '_'),  # Underscore variant
            cve_lower.replace('-', ' '),  # Space variant
            cve_lower.replace('-', ''),   # No separator
            f"cve{cve_year}{cve_number}", # Compact format
            f"{cve_year}_{cve_number}",   # Year_number format
        ]
        cve_mentioned = any(pattern in repo_name or pattern in description 
                        for pattern in cve_patterns)
        strong_indicators = {
            'exploit': 3,
            'poc': 3,
            'proof': 2,
            'concept': 2,
            'vulnerability': 2,
            'cve': 2,
            'security': 1,
            'pentest': 2,
            'hack': 1,
            'attack': 1,
            'payload': 2,
            'rce': 2,  # Remote code execution
            'bypass': 2,
            '0day': 3,
            'zero-day': 3,
        }
        indicator_score = sum(weight for keyword, weight in strong_indicators.items()
                            if keyword in repo_name or keyword in description)
        stars = repo.get('stargazers_count', 0)
        size = repo.get('size', 0)
        forks = repo.get('forks_count', 0)
        if size < 5 and stars == 0 and forks == 0:
            return False
        exclude_keywords = [
            'awesome', 'list', 'collection', 'tutorial', 'learning',
            'book', 'course', 'guide', 'reference', 'documentation',
            'template', 'boilerplate', 'framework', 'library',
            'dashboard', 'monitoring', 'scanner', 'checker', 'notes',
            'cheatsheet', 'resources', 'bookmark', 'archive'
        ]
        exclude_score = sum(1 for keyword in exclude_keywords 
                        if keyword in repo_name or keyword in description)
        if cve_mentioned:
            return exclude_score < 3 and (indicator_score >= 1 or stars >= 2)
        elif indicator_score >= 4:
            return exclude_score < 2
        elif indicator_score >= 2:
            return exclude_score < 2 and (stars >= 5 or forks >= 2)
        else:
            return False

    def calculate_relevance_score(self, repo: Dict, cve_id: str) -> float:
        """Enhanced relevance score calculation with better GitHub metrics"""
        score = 0.0
        
        repo_name = (repo.get('full_name') or '').lower()
        description = (repo.get('description') or '').lower()
        if cve_id.lower() in repo_name:
            score += 60  # Increased from 50
        if cve_id.lower() in description:
            score += 40  # Increased from 30
        poc_keywords = {
            'exploit': 30,     # Increased
            'poc': 30,         # Increased  
            'proof of concept': 30,
            'vulnerability': 20, # Increased
            'cve': 20,         # Increased
            'security': 12,    # Slightly increased
            'pentest': 15,     # New
            'hack': 10,        # New
            'attack': 8        # New
        }
        
        for keyword, points in poc_keywords.items():
            if keyword in repo_name:
                score += points
            if keyword in description:
                score += points * 0.8  # Slightly higher multiplier
        stars = repo.get('stargazers_count', 0)
        forks = repo.get('forks_count', 0)
        if stars > 0:
            import math
            if stars >= 1000:
                score += 40
            elif stars >= 500:
                score += 35
            elif stars >= 100:
                score += 30
            elif stars >= 50:
                score += 25
            elif stars >= 20:
                score += 20
            elif stars >= 10:
                score += 15
            elif stars >= 5:
                score += 10
            else:
                score += min(8, math.log10(stars + 1) * 3)
        if forks > 0:
            if forks >= 100:
                score += 25
            elif forks >= 50:
                score += 20
            elif forks >= 20:
                score += 15
            elif forks >= 10:
                score += 12
            elif forks >= 5:
                score += 8
            else:
                score += min(5, forks)
        try:
            updated_at = repo.get('updated_at', '')
            if updated_at:
                from datetime import datetime
                import re
                date_clean = re.sub(r'[TZ].*$', '', updated_at)
                updated_date = datetime.fromisoformat(date_clean)
                days_old = (datetime.now() - updated_date).days
                if days_old <= 30:
                    score += 25
                elif days_old <= 90:
                    score += 20
                elif days_old <= 180:
                    score += 15
                elif days_old <= 365:
                    score += 10
                elif days_old <= 730:
                    score += 5
        except Exception:
            pass  # Skip if date parsing fails
        size = repo.get('size', 0)
        if 50 <= size <= 50000:  # Sweet spot for POC repos
            score += 15
        elif 10 <= size <= 100000:
            score += 10
        elif size > 0:
            score += 5
        language = (repo.get('language') or '').lower()
        language_scores = {
            'python': 15,      # Most common for security tools
            'c': 12,           # Common for exploits
            'c++': 12,
            'go': 10,          # Growing in security space
            'rust': 10,
            'java': 8,
            'javascript': 8,   # Web exploits
            'shell': 12,       # Exploit scripts
            'powershell': 10,  # Windows exploits
            'bash': 8,
            'php': 6,
            'ruby': 6
        }
        score += language_scores.get(language, 0)
        open_issues = repo.get('open_issues_count', 0)
        if open_issues == 0:
            score += 5  # Well-maintained
        elif open_issues <= 5:
            score += 3
        elif open_issues > 20:
            score -= 5  # Potentially abandoned
        exploit_patterns = ['exploit', 'poc', 'cve', 'vuln', 'security', 'pentest']
        pattern_matches = sum(1 for pattern in exploit_patterns if pattern in repo_name)
        score += pattern_matches * 5
        
        return score

    def search_alternative_platforms(self, cve_id: str) -> List[Dict]:
        """Search alternative platforms for POCs and exploits"""
        alternative_results = []
        
        try:
            platforms = [
                self.search_exploit_db(cve_id),
                self.search_packetstorm(cve_id),
                self.search_rapid7_db(cve_id)
            ]
            
            for platform_results in platforms:
                if platform_results:
                    alternative_results.extend(platform_results)
                    
        except Exception as e:
            with self.lock:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Alternative platform search error: {e}")
                
        return alternative_results

    def search_exploit_db(self, cve_id: str) -> List[Dict]:
        """Search Exploit-DB for exploits (web scraping approach)"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            return [{
                'platform': 'Exploit-DB',
                'title': f'Search results for {normalized_cve}',
                'url': f'https://www.exploit-db.com/search?cve={normalized_cve}',
                'description': 'Manual verification required',
                'type': 'search_link'
            }]
            
        except Exception:
            return []

    def search_packetstorm(self, cve_id: str) -> List[Dict]:
        """Search PacketStorm Security"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            
            return [{
                'platform': 'PacketStorm',
                'title': f'Search results for {normalized_cve}',
                'url': f'https://packetstormsecurity.com/search/?q={normalized_cve}',
                'description': 'Manual verification required',
                'type': 'search_link'
            }]
            
        except Exception:
            return []

    def search_rapid7_db(self, cve_id: str) -> List[Dict]:
        """Search Rapid7 Vulnerability Database"""
        try:
            normalized_cve = self.normalize_cve_id(cve_id)
            
            return [{
                'platform': 'Rapid7',
                'title': f'Vulnerability details for {normalized_cve}',
                'url': f'https://www.rapid7.com/db/?q={normalized_cve}',
                'description': 'Comprehensive vulnerability details',
                'type': 'search_link'
            }]
            
        except Exception:
            return []

    def search_poc_comprehensive(self, cve_id: str) -> List[Dict]:
        """Comprehensive POC search across multiple platforms"""
        all_pocs = []
        
        with self.lock:
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Searching for POCs across multiple platforms...")
        github_repos = self.search_github_repositories(cve_id)
        if github_repos:
            all_pocs.extend(github_repos)
        github_code = self.search_github_code(cve_id)
        if github_code:
            all_pocs.extend(github_code)
        alt_platforms = self.search_alternative_platforms(cve_id)
        if alt_platforms:
            all_pocs.extend(alt_platforms)
        seen_urls = set()
        unique_pocs = []
        
        for poc in all_pocs:
            url = poc.get('html_url') or poc.get('url', '')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_pocs.append(poc)
        unique_pocs.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        
        return unique_pocs

    def analyze_poc_quality(self, poc_results: List[Dict]) -> List[Dict]:
        """Analyze POC quality and add intelligence"""
        analyzed_pocs = []
        
        for poc in poc_results:
            try:
                if poc.get('type') == 'search_link':
                    poc['analysis'] = {
                        'quality_score': 50,  # Neutral score for manual verification
                        'quality_level': 'MANUAL_CHECK',
                        'platform': poc.get('platform', 'Unknown'),
                        'requires_verification': True
                    }
                    analyzed_pocs.append(poc)
                    continue
                stars = poc.get('stargazers_count', 0)
                forks = poc.get('forks_count', 0)
                issues = poc.get('open_issues_count', 0)
                updated = poc.get('updated_at', '')
                language = poc.get('language', 'Unknown')
                size = poc.get('size', 0)
                quality_score = 0
                if stars >= 100: quality_score += 30
                elif stars >= 50: quality_score += 25
                elif stars >= 20: quality_score += 20
                elif stars >= 10: quality_score += 15
                elif stars >= 5: quality_score += 10
                elif stars >= 1: quality_score += 5
                if forks >= 50: quality_score += 20
                elif forks >= 20: quality_score += 15
                elif forks >= 10: quality_score += 10
                elif forks >= 5: quality_score += 5
                try:
                    if updated:
                        from datetime import datetime
                        updated_date = datetime.fromisoformat(updated.replace('Z', '+00:00'))
                        days_old = (datetime.now().astimezone() - updated_date).days
                        if days_old <= 30: quality_score += 20
                        elif days_old <= 90: quality_score += 15
                        elif days_old <= 365: quality_score += 10
                        elif days_old <= 730: quality_score += 5
                except:
                    pass
                reliable_languages = ['Python', 'C', 'C++', 'Java', 'Go', 'Rust']
                if language in reliable_languages:
                    quality_score += 15
                elif language in ['JavaScript', 'PHP', 'Ruby', 'Perl']:
                    quality_score += 10
                elif language:
                    quality_score += 5
                if 100 <= size <= 10000: quality_score += 10
                elif 10 <= size <= 100000: quality_score += 5
                if issues < 10: quality_score += 5
                relevance_bonus = min(20, poc.get('relevance_score', 0) * 0.2)
                quality_score += relevance_bonus
                if quality_score >= 80: quality_level = "EXCELLENT"
                elif quality_score >= 60: quality_level = "GOOD"
                elif quality_score >= 40: quality_level = "FAIR"
                elif quality_score >= 20: quality_level = "POOR"
                else: quality_level = "VERY_POOR"
                
                poc['analysis'] = {
                    'quality_score': quality_score,
                    'quality_level': quality_level,
                    'language': language,
                    'last_updated': updated,
                    'stars': stars,
                    'forks': forks,
                    'size_kb': round(size / 1024, 2) if size > 0 else 0,
                    'source': poc.get('source', 'github_repo_search')
                }
                
                analyzed_pocs.append(poc)
                
            except Exception as e:
                poc['analysis'] = {
                    'quality_score': 0,
                    'quality_level': 'UNKNOWN',
                    'error': str(e)
                }
                analyzed_pocs.append(poc)
                
        return analyzed_pocs

    def export_results(self, cve_data_list: List[Dict], format_type: str, filename: Optional[str] = None) -> str:
        """Enhanced export with reference URLs in CSV and better error handling"""
        try:
            export_dir = Path(self.config.get('export', {}).get('directory', './cvehawk_reports'))
            export_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if not filename:
                filename = f"cvehawk_report_{timestamp}"
                
            if format_type.lower() == 'json':
                filepath = export_dir / f"{filename}.json"
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(cve_data_list, f, indent=2, default=str, ensure_ascii=False)
                    
            elif format_type.lower() == 'html':
                filepath = export_dir / f"{filename}.html"
                html_content = self.generate_html_report(cve_data_list)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            elif format_type.lower() == 'csv':
                filepath = export_dir / f"{filename}.csv"
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    headers = [
                        'CVE_ID', 'Severity', 'CVSS_Score', 'EPSS_Score', 'EPSS_Percentile',
                        'Description', 'Published', 'Last_Modified', 'Reference_URLs', 
                        'POC_Count', 'Top_POC_URL', 'Top_POC_Stars', 'Top_POC_Quality'
                    ]
                    writer.writerow(headers)
                    
                    for cve_data in cve_data_list:
                        try:
                            cve_info = cve_data.get('cve_info', {})
                            cve_id = cve_data.get('cve_id', 'Unknown')
                            severity = cve_data.get('severity', 'unknown')
                            cvss_score = cve_data.get('cvss_score', 'N/A')
                            epss_score = cve_data.get('epss_score', '')
                            epss_percentile = cve_data.get('epss_percentile', '')
                            descriptions = cve_info.get('descriptions', [])
                            description = ''
                            if descriptions and len(descriptions) > 0:
                                description = descriptions[0].get('value', '')[:300]  # Limit length
                            published = cve_info.get('published', '')[:10] if cve_info.get('published') else ''
                            last_modified = cve_info.get('lastModified', '')[:10] if cve_info.get('lastModified') else ''
                            reference_urls = cve_data.get('reference_urls', [])
                            ref_urls_str = '; '.join(reference_urls[:5])  # Limit to 5 URLs
                            poc_results = cve_data.get('poc_results', [])
                            poc_count = len(poc_results)
                            
                            top_poc_url = ''
                            top_poc_stars = ''
                            top_poc_quality = ''
                            
                            if poc_results:
                                github_pocs = [p for p in poc_results if p.get('html_url') and 'github.com' in p.get('html_url', '')]
                                if github_pocs:
                                    top_poc = github_pocs[0]  # Already sorted by relevance
                                    top_poc_url = top_poc.get('html_url', '')
                                    top_poc_stars = str(top_poc.get('stargazers_count', 0))
                                    analysis = top_poc.get('analysis', {})
                                    top_poc_quality = f"{analysis.get('quality_level', 'UNKNOWN')} ({analysis.get('quality_score', 0):.0f}/100)"
                            row = [
                                cve_id, severity, cvss_score, epss_score, epss_percentile,
                                description, published, last_modified, ref_urls_str,
                                poc_count, top_poc_url, top_poc_stars, top_poc_quality
                            ]
                            writer.writerow(row)
                            
                        except Exception as row_error:
                            error_row = [
                                cve_data.get('cve_id', 'Unknown'), 'ERROR', '', '', '',
                                f'Export error: {str(row_error)}', '', '', '', '', '', '', ''
                            ]
                            writer.writerow(error_row)
                            
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
                
            return str(filepath)
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Export failed: {e}")
            return ""

    def generate_html_report(self, cve_data_list: List[Dict]) -> str:
        """Generate professional HTML report with modern design"""
        def safe_html_text(text):
            """Safely encode text for HTML"""
            if not text:
                return ''
            text = str(text).replace('🦅', '&#x1F985;').replace('🔥', '&#x1F525;').replace('⚠️', '&#x26A0;').replace('📊', '&#x1F4CA;').replace('✅', '&#x2705;').replace('🎯', '&#x1F3AF;').replace('🔍', '&#x1F50D;').replace('⭐', '&#x2B50;').replace('👑', '&#x1F451;').replace('🥇', '&#x1F947;').replace('🥈', '&#x1F948;').replace('📌', '&#x1F4CC;')
            return html.escape(text)
        total_cves = len(cve_data_list)
        cves_with_pocs = sum(1 for cve in cve_data_list if cve.get('poc_results'))
        total_pocs = sum(len(cve.get('poc_results', [])) for cve in cve_data_list)
        critical_high = sum(1 for cve in cve_data_list if cve.get('severity', '').lower() in ['critical', 'high'])
        
        html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CVEHawk Security Report - Professional Edition</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            :root {{
                --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --danger-gradient: linear-gradient(135deg, #f93b1d 0%, #ea1e63 100%);
                --success-gradient: linear-gradient(135deg, #00b09b 0%, #96c93d 100%);
                --warning-gradient: linear-gradient(135deg, #f7971e 0%, #ffd200 100%);
                --dark-bg: #0a0a0f;
                --card-bg: #13131a;
                --card-border: rgba(255, 255, 255, 0.08);
                --text-primary: #ffffff;
                --text-secondary: #a8a8b3;
                --text-muted: #6b6b7b;
            }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--dark-bg);
                color: var(--text-primary);
                line-height: 1.6;
                min-height: 100vh;
                position: relative;
            }}
            
            body::before {{
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 20% 50%, rgba(102, 126, 234, 0.1) 0%, transparent 50%),
                            radial-gradient(circle at 80% 80%, rgba(118, 75, 162, 0.1) 0%, transparent 50%),
                            radial-gradient(circle at 40% 20%, rgba(102, 126, 234, 0.05) 0%, transparent 50%);
                pointer-events: none;
                z-index: 0;
            }}
            
            .container {{
                max-width: 1440px;
                margin: 0 auto;
                padding: 20px;
                position: relative;
                z-index: 1;
            }}
            
            /* Enhanced Header */
            .header {{
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: 24px;
                padding: 60px 40px;
                margin-bottom: 40px;
                position: relative;
                overflow: hidden;
                backdrop-filter: blur(20px);
            }}
            
            .header::before {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: var(--primary-gradient);
                opacity: 0.1;
                animation: rotate 30s linear infinite;
            }}
            
            @keyframes rotate {{
                from {{ transform: rotate(0deg); }}
                to {{ transform: rotate(360deg); }}
            }}
            
            .header-content {{
                position: relative;
                z-index: 1;
                text-align: center;
            }}
            
            .logo {{
                font-size: 4em;
                margin-bottom: 20px;
                filter: drop-shadow(0 0 30px rgba(102, 126, 234, 0.5));
                animation: pulse 2s ease-in-out infinite;
            }}
            
            @keyframes pulse {{
                0%, 100% {{ transform: scale(1); }}
                50% {{ transform: scale(1.05); }}
            }}
            
            .header h1 {{
                font-size: 3.5em;
                font-weight: 800;
                background: var(--primary-gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 15px;
                letter-spacing: -2px;
            }}
            
            .header .subtitle {{
                font-size: 1.2em;
                color: var(--text-secondary);
                margin-bottom: 10px;
            }}
            
            .header .timestamp {{
                font-size: 0.95em;
                color: var(--text-muted);
                font-weight: 500;
            }}
            
            /* Statistics Grid */
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 24px;
                margin-bottom: 50px;
            }}
            
            .stat-card {{
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: 16px;
                padding: 30px;
                position: relative;
                overflow: hidden;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: var(--primary-gradient);
                opacity: 0;
                transition: opacity 0.3s ease;
            }}
            
            .stat-card:hover {{
                transform: translateY(-5px);
                border-color: rgba(102, 126, 234, 0.3);
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            }}
            
            .stat-card:hover::before {{
                opacity: 1;
            }}
            
            .stat-icon {{
                width: 56px;
                height: 56px;
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5em;
                margin-bottom: 20px;
            }}
            
            .stat-icon.primary {{
                background: rgba(102, 126, 234, 0.15);
                color: #667eea;
            }}
            
            .stat-icon.success {{
                background: rgba(0, 176, 155, 0.15);
                color: #00b09b;
            }}
            
            .stat-icon.warning {{
                background: rgba(247, 151, 30, 0.15);
                color: #f7971e;
            }}
            
            .stat-icon.danger {{
                background: rgba(249, 59, 29, 0.15);
                color: #f93b1d;
            }}
            
            .stat-value {{
                font-size: 2.8em;
                font-weight: 700;
                margin-bottom: 8px;
                background: linear-gradient(135deg, #fff 0%, #a8a8b3 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .stat-label {{
                font-size: 0.95em;
                color: var(--text-secondary);
                text-transform: uppercase;
                letter-spacing: 1px;
                font-weight: 600;
            }}
            
            /* CVE Card Container */
            .cve-card {{
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: 20px;
                margin-bottom: 32px;
                overflow: hidden;
                transition: all 0.3s ease;
                position: relative;
                backdrop-filter: blur(10px);
            }}
            
            .cve-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 6px;
                height: 100%;
                opacity: 0;
                transition: opacity 0.3s ease;
            }}
            
            .cve-card.severity-critical::before {{
                background: var(--danger-gradient);
                opacity: 1;
            }}
            
            .cve-card.severity-high::before {{
                background: linear-gradient(135deg, #ff6b6b 0%, #ff8e53 100%);
                opacity: 1;
            }}
            
            .cve-card.severity-medium::before {{
                background: var(--warning-gradient);
                opacity: 1;
            }}
            
            .cve-card.severity-low::before {{
                background: var(--success-gradient);
                opacity: 1;
            }}
            
            .cve-card:hover {{
                transform: translateX(5px);
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
                border-color: rgba(102, 126, 234, 0.2);
            }}
            
            /* CVE Header */
            .cve-header {{
                padding: 28px 32px;
                background: rgba(255, 255, 255, 0.02);
                border-bottom: 1px solid var(--card-border);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 20px;
            }}
            
            .cve-title {{
                display: flex;
                align-items: center;
                gap: 16px;
            }}
            
            .cve-id {{
                font-size: 1.8em;
                font-weight: 700;
                background: linear-gradient(135deg, #00ffff 0%, #667eea 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .cve-meta {{
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }}
            
            .badge {{
                padding: 8px 16px;
                border-radius: 100px;
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                display: inline-flex;
                align-items: center;
                gap: 6px;
                transition: all 0.2s ease;
            }}
            
            .badge:hover {{
                transform: scale(1.05);
            }}
            
            .badge.severity-critical {{
                background: rgba(249, 59, 29, 0.15);
                color: #ff4444;
                border: 1px solid rgba(249, 59, 29, 0.3);
            }}
            
            .badge.severity-high {{
                background: rgba(255, 107, 107, 0.15);
                color: #ff6b6b;
                border: 1px solid rgba(255, 107, 107, 0.3);
            }}
            
            .badge.severity-medium {{
                background: rgba(247, 151, 30, 0.15);
                color: #f7971e;
                border: 1px solid rgba(247, 151, 30, 0.3);
            }}
            
            .badge.severity-low {{
                background: rgba(0, 176, 155, 0.15);
                color: #00b09b;
                border: 1px solid rgba(0, 176, 155, 0.3);
            }}
            
            .badge.severity-unknown {{
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-secondary);
                border: 1px solid var(--card-border);
            }}
            
            .badge.cvss {{
                background: rgba(102, 126, 234, 0.15);
                color: #667eea;
                border: 1px solid rgba(102, 126, 234, 0.3);
            }}
            
            .badge.date {{
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-muted);
                border: 1px solid var(--card-border);
            }}
            
            /* CVE Body */
            .cve-body {{
                padding: 32px;
            }}
            
            /* Section Styling */
            .section {{
                margin-bottom: 32px;
            }}
            
            .section:last-child {{
                margin-bottom: 0;
            }}
            
            .section-header {{
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 20px;
            }}
            
            .section-icon {{
                width: 36px;
                height: 36px;
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(102, 126, 234, 0.1);
                color: #667eea;
                font-size: 1.2em;
            }}
            
            .section-title {{
                font-size: 1.3em;
                font-weight: 600;
                color: var(--text-primary);
            }}
            
            /* Description Box */
            .description-box {{
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid var(--card-border);
                border-radius: 12px;
                padding: 24px;
                line-height: 1.8;
                color: var(--text-secondary);
                position: relative;
                overflow: hidden;
            }}
            
            .description-box::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 4px;
                height: 100%;
                background: var(--primary-gradient);
            }}
            
            /* EPSS Card */
            .epss-container {{
                background: linear-gradient(135deg, rgba(102, 126, 234, 0.05), rgba(118, 75, 162, 0.05));
                border: 1px solid rgba(102, 126, 234, 0.2);
                border-radius: 16px;
                padding: 28px;
                position: relative;
                overflow: hidden;
            }}
            
            .epss-container::before {{
                content: '';
                position: absolute;
                top: -50%;
                right: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle, rgba(102, 126, 234, 0.1) 0%, transparent 70%);
                animation: pulse 4s ease-in-out infinite;
            }}
            
            .epss-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 24px;
                position: relative;
                z-index: 1;
            }}
            
            .epss-item {{
                text-align: center;
                padding: 16px;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 12px;
                transition: all 0.3s ease;
            }}
            
            .epss-item:hover {{
                background: rgba(0, 0, 0, 0.3);
                transform: translateY(-2px);
            }}
            
            .epss-value {{
                font-size: 2.2em;
                font-weight: 700;
                margin-bottom: 8px;
                background: linear-gradient(135deg, #f7971e 0%, #ffd200 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .epss-label {{
                font-size: 0.9em;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .risk-indicator {{
                display: inline-block;
                padding: 6px 14px;
                border-radius: 100px;
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-top: 8px;
            }}
            
            .risk-critical {{
                background: rgba(249, 59, 29, 0.15);
                color: #ff4444;
                border: 1px solid rgba(249, 59, 29, 0.3);
            }}
            
            .risk-high {{
                background: rgba(255, 107, 107, 0.15);
                color: #ff6b6b;
                border: 1px solid rgba(255, 107, 107, 0.3);
            }}
            
            .risk-medium {{
                background: rgba(247, 151, 30, 0.15);
                color: #f7971e;
                border: 1px solid rgba(247, 151, 30, 0.3);
            }}
            
            .risk-low {{
                background: rgba(0, 176, 155, 0.15);
                color: #00b09b;
                border: 1px solid rgba(0, 176, 155, 0.3);
            }}
            
            /* POC Cards */
            .poc-container {{
                display: grid;
                gap: 16px;
            }}
            
            .poc-card {{
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid var(--card-border);
                border-radius: 14px;
                padding: 24px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }}
            
            .poc-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 3px;
                background: linear-gradient(90deg, transparent, #00ffff, transparent);
                transform: translateX(-100%);
                transition: transform 0.6s ease;
            }}
            
            .poc-card:hover::before {{
                transform: translateX(100%);
            }}
            
            .poc-card:hover {{
                background: rgba(0, 0, 0, 0.4);
                transform: translateY(-3px);
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                border-color: rgba(0, 255, 255, 0.2);
            }}
            
            .poc-rank {{
                position: absolute;
                top: 20px;
                right: 20px;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1.1em;
            }}
            
            .poc-rank.rank-1 {{
                background: linear-gradient(135deg, #ffd700 0%, #ffed4e 100%);
                color: #000;
                box-shadow: 0 0 20px rgba(255, 215, 0, 0.5);
            }}
            
            .poc-rank.rank-2 {{
                background: linear-gradient(135deg, #c0c0c0 0%, #e8e8e8 100%);
                color: #000;
            }}
            
            .poc-rank.rank-3 {{
                background: linear-gradient(135deg, #cd7f32 0%, #e3a857 100%);
                color: #fff;
            }}
            
            .poc-rank.rank-other {{
                background: rgba(102, 126, 234, 0.1);
                color: #667eea;
                border: 1px solid rgba(102, 126, 234, 0.3);
            }}
            
            .poc-header {{
                margin-bottom: 16px;
            }}
            
            .poc-title {{
                font-size: 1.15em;
                font-weight: 600;
                margin-bottom: 8px;
            }}
            
            .poc-title a {{
                color: #00ffff;
                text-decoration: none;
                transition: all 0.2s ease;
            }}
            
            .poc-title a:hover {{
                color: #667eea;
                text-decoration: underline;
            }}
            
            .poc-description {{
                color: var(--text-secondary);
                font-size: 0.95em;
                line-height: 1.6;
                margin-bottom: 16px;
            }}
            
            .poc-metrics {{
                display: flex;
                gap: 16px;
                flex-wrap: wrap;
            }}
            
            .poc-metric {{
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 6px 12px;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid var(--card-border);
                border-radius: 8px;
                font-size: 0.9em;
                color: var(--text-secondary);
                transition: all 0.2s ease;
            }}
            
            .poc-metric:hover {{
                background: rgba(255, 255, 255, 0.05);
                border-color: rgba(102, 126, 234, 0.3);
            }}
            
            .poc-metric.stars {{
                color: #ffd700;
                border-color: rgba(255, 215, 0, 0.2);
            }}
            
            .poc-metric.forks {{
                color: #00b09b;
                border-color: rgba(0, 176, 155, 0.2);
            }}
            
            .poc-metric.language {{
                color: #667eea;
                border-color: rgba(102, 126, 234, 0.2);
            }}
            
            .poc-metric.quality-excellent {{
                background: rgba(0, 176, 155, 0.1);
                color: #00b09b;
                border-color: rgba(0, 176, 155, 0.3);
            }}
            
            .poc-metric.quality-good {{
                background: rgba(102, 126, 234, 0.1);
                color: #667eea;
                border-color: rgba(102, 126, 234, 0.3);
            }}
            
            .poc-metric.quality-fair {{
                background: rgba(247, 151, 30, 0.1);
                color: #f7971e;
                border-color: rgba(247, 151, 30, 0.3);
            }}
            
            .poc-metric.quality-poor {{
                background: rgba(249, 59, 29, 0.1);
                color: #ff4444;
                border-color: rgba(249, 59, 29, 0.3);
            }}
            
            /* References */
            .references-grid {{
                display: grid;
                gap: 12px;
                max-height: 300px;
                overflow-y: auto;
                padding: 16px;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 12px;
                border: 1px solid var(--card-border);
            }}
            
            .references-grid::-webkit-scrollbar {{
                width: 8px;
            }}
            
            .references-grid::-webkit-scrollbar-track {{
                background: rgba(255, 255, 255, 0.02);
                border-radius: 4px;
            }}
            
            .references-grid::-webkit-scrollbar-thumb {{
                background: rgba(102, 126, 234, 0.3);
                border-radius: 4px;
            }}
            
            .references-grid::-webkit-scrollbar-thumb:hover {{
                background: rgba(102, 126, 234, 0.5);
            }}
            
            .reference-item {{
                padding: 12px 16px;
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid var(--card-border);
                border-radius: 8px;
                transition: all 0.2s ease;
            }}
            
            .reference-item:hover {{
                background: rgba(255, 255, 255, 0.04);
                border-color: rgba(102, 126, 234, 0.3);
                transform: translateX(5px);
            }}
            
            .reference-item a {{
                color: #667eea;
                text-decoration: none;
                font-size: 0.95em;
                word-break: break-all;
            }}
            
            .reference-item a:hover {{
                color: #00ffff;
                text-decoration: underline;
            }}
            
            /* No POCs Message */
            .no-pocs {{
                text-align: center;
                padding: 48px;
                background: rgba(247, 151, 30, 0.05);
                border: 1px solid rgba(247, 151, 30, 0.2);
                border-radius: 16px;
            }}
            
            .no-pocs-icon {{
                font-size: 3em;
                margin-bottom: 16px;
                opacity: 0.5;
            }}
            
            .no-pocs-title {{
                font-size: 1.3em;
                font-weight: 600;
                color: #f7971e;
                margin-bottom: 12px;
            }}
            
            .no-pocs-text {{
                color: var(--text-secondary);
                font-size: 0.95em;
                line-height: 1.6;
            }}
            
            /* Footer */
            .footer {{
                margin-top: 80px;
                padding: 40px;
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: 20px;
                text-align: center;
                position: relative;
                overflow: hidden;
            }}
            
            .footer::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--primary-gradient);
            }}
            
            .footer-logo {{
                font-size: 2.5em;
                font-weight: 800;
                background: var(--primary-gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 16px;
            }}
            
            .footer-text {{
                color: var(--text-secondary);
                margin-bottom: 8px;
            }}
            
            .footer-author {{
                color: #667eea;
                font-weight: 600;
            }}
            
            /* Animations */
            @keyframes fadeIn {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .cve-card {{
                animation: fadeIn 0.5s ease-out;
                animation-fill-mode: both;
            }}
            
            .cve-card:nth-child(1) {{ animation-delay: 0.1s; }}
            .cve-card:nth-child(2) {{ animation-delay: 0.2s; }}
            .cve-card:nth-child(3) {{ animation-delay: 0.3s; }}
            .cve-card:nth-child(4) {{ animation-delay: 0.4s; }}
            .cve-card:nth-child(5) {{ animation-delay: 0.5s; }}
            
            /* Responsive Design */
            @media (max-width: 768px) {{
                .container {{
                    padding: 15px;
                }}
                
                .header h1 {{
                    font-size: 2em;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .cve-header {{
                    padding: 20px;
                }}
                
                .cve-id {{
                    font-size: 1.4em;
                }}
                
                .epss-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Enhanced Header -->
            <div class="header">
                <div class="header-content">
                    <div class="logo">&#x1F985;</div>
                    <h1>CVEHawk Security Report</h1>
                    <div class="subtitle">Professional Vulnerability Intelligence Platform</div>
                    <div class="timestamp">Generated: {safe_html_text(datetime.now().strftime("%B %d, %Y at %H:%M:%S UTC"))}</div>
                </div>
            </div>
            
            <!-- Statistics Dashboard -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon primary">&#x1F4CA;</div>
                    <div class="stat-value">{total_cves}</div>
                    <div class="stat-label">CVEs Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon success">&#x1F50D;</div>
            <div class="stat-value">{cves_with_pocs}</div>
                    <div class="stat-label">CVEs with POCs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon warning">&#x1F4E6;</div>
                    <div class="stat-value">{total_pocs}</div>
                    <div class="stat-label">Total POCs Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon danger">&#x26A0;</div>
                    <div class="stat-value">{critical_high}</div>
                    <div class="stat-label">High Risk CVEs</div>
                </div>
            </div>
            
            <!-- CVE Cards -->
            <div class="cve-list">
    """
        for idx, cve_data in enumerate(cve_data_list):
            cve_id = safe_html_text(cve_data.get('cve_id', 'Unknown'))
            cve_info = cve_data.get('cve_info', {})
            severity = cve_data.get('severity', 'unknown').lower()
            cvss_score = cve_data.get('cvss_score', 'N/A')
            published = cve_info.get('published', '')
            pub_date = published[:10] if published else 'Unknown'
            
            html_content += f"""
                <div class="cve-card severity-{severity}">
                    <!-- CVE Header -->
                    <div class="cve-header">
                        <div class="cve-title">
                            <div class="cve-id">{cve_id}</div>
                        </div>
                        <div class="cve-meta">
                            <span class="badge severity-{severity}">
                                {safe_html_text(severity.upper())}
                            </span>
                            <span class="badge cvss">
                                CVSS {safe_html_text(str(cvss_score))}
                            </span>
                            <span class="badge date">
                                &#x1F4C5; {safe_html_text(pub_date)}
                            </span>
                        </div>
                    </div>
                    
                    <!-- CVE Body -->
                    <div class="cve-body">
    """
            descriptions = cve_info.get('descriptions', [])
            if descriptions:
                desc_text = safe_html_text(descriptions[0].get('value', ''))
                html_content += f"""
                        <div class="section">
                            <div class="section-header">
                                <div class="section-icon">&#x1F4DD;</div>
                                <div class="section-title">Description</div>
                            </div>
                            <div class="description-box">
                                {desc_text}
                            </div>
                        </div>
    """
            if cve_data.get('epss_data'):
                epss = cve_data['epss_data']
                epss_score = epss.get('epss_score', 0)
                epss_percentile = epss.get('epss_percentile', 0)
                if epss_score >= 0.7:
                    risk_level = "CRITICAL"
                    risk_class = "risk-critical"
                    risk_icon = "&#x1F525;"
                elif epss_score >= 0.3:
                    risk_level = "HIGH"
                    risk_class = "risk-high"
                    risk_icon = "&#x26A0;"
                elif epss_score >= 0.1:
                    risk_level = "MEDIUM"
                    risk_class = "risk-medium"
                    risk_icon = "&#x1F4CA;"
                else:
                    risk_level = "LOW"
                    risk_class = "risk-low"
                    risk_icon = "&#x2705;"
                
                html_content += f"""
                        <div class="section">
                            <div class="section-header">
                                <div class="section-icon">&#x1F3AF;</div>
                                <div class="section-title">Exploit Prediction Scoring System (EPSS)</div>
                            </div>
                            <div class="epss-container">
                                <div class="epss-grid">
                                    <div class="epss-item">
                                        <div class="epss-value">{epss_score:.4f}</div>
                                        <div class="epss-label">EPSS Score</div>
                                    </div>
                                    <div class="epss-item">
                                        <div class="epss-value">{epss_score*100:.2f}%</div>
                                        <div class="epss-label">Exploit Probability</div>
                                    </div>
                                    <div class="epss-item">
                                        <div class="epss-value">{epss_percentile:.1f}%</div>
                                        <div class="epss-label">Percentile Rank</div>
                                    </div>
                                    <div class="epss-item">
                                        <div class="epss-value">{risk_icon}</div>
                                        <div class="epss-label">Risk Assessment</div>
                                        <div class="risk-indicator {risk_class}">{risk_level}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
    """
            poc_results = cve_data.get('poc_results', [])
            if poc_results:
                github_pocs = [p for p in poc_results if p.get('html_url') and 'github.com' in p.get('html_url', '')]
                github_pocs.sort(key=lambda x: (
                    x.get('stargazers_count', 0) * 1000 + 
                    x.get('forks_count', 0) * 100
                ), reverse=True)
                
                alt_pocs = [p for p in poc_results if p.get('type') == 'search_link']
                
                html_content += f"""
                        <div class="section">
                            <div class="section-header">
                                <div class="section-icon">&#x1F50D;</div>
                                <div class="section-title">Proof of Concepts ({len(poc_results)} discovered)</div>
                            </div>
                            <div class="poc-container">
    """
                for i, poc in enumerate(github_pocs[:10], 1):
                    repo_name = safe_html_text(poc.get('full_name', 'Unknown'))
                    html_url = safe_html_text(poc.get('html_url', ''))
                    description = safe_html_text(poc.get('description', 'No description available'))[:200]
                    stars = poc.get('stargazers_count', 0)
                    forks = poc.get('forks_count', 0)
                    
                    analysis = poc.get('analysis', {})
                    quality_level = analysis.get('quality_level', 'UNKNOWN').lower()
                    quality_score = analysis.get('quality_score', 0)
                    language = safe_html_text(analysis.get('language', 'Unknown'))
                    if i == 1:
                        rank_class = "rank-1"
                        rank_icon = "&#x1F451;"
                    elif i == 2:
                        rank_class = "rank-2"
                        rank_icon = "&#x1F948;"
                    elif i == 3:
                        rank_class = "rank-3"
                        rank_icon = "&#x1F949;"
                    else:
                        rank_class = "rank-other"
                        rank_icon = f"#{i}"
                    quality_class = f"quality-{quality_level.replace('_', '-').lower()}"
                    if quality_level == 'UNKNOWN':
                        quality_class = "quality-poor"
                    
                    html_content += f"""
                                <div class="poc-card">
                                    <div class="poc-rank {rank_class}">{rank_icon}</div>
                                    <div class="poc-header">
                                        <div class="poc-title">
                                            <a href="{html_url}" target="_blank" rel="noopener noreferrer">
                                                {repo_name}
                                            </a>
                                        </div>
                                    </div>
                                    <div class="poc-description">
                                        {description}{'...' if len(description) >= 200 else ''}
                                    </div>
                                    <div class="poc-metrics">
                                        <div class="poc-metric stars">
                                            &#x2B50; {stars:,} stars
                                        </div>
                                        <div class="poc-metric forks">
                                            &#x1F500; {forks:,} forks
                                        </div>
                                        <div class="poc-metric language">
                                            &#x1F4BB; {language}
                                        </div>
                                        <div class="poc-metric {quality_class}">
                                            {safe_html_text(quality_level.replace('_', ' ').title())} ({quality_score:.0f}/100)
                                        </div>
                                    </div>
                                </div>
    """
                for poc in alt_pocs:
                    platform = safe_html_text(poc.get('analysis', {}).get('platform', 'External'))
                    url = safe_html_text(poc.get('url', ''))
                    
                    html_content += f"""
                                <div class="poc-card">
                                    <div class="poc-header">
                                        <div class="poc-title">
                                            <a href="{url}" target="_blank" rel="noopener noreferrer">
                                                &#x1F517; {platform} Search Results
                                            </a>
                                        </div>
                                    </div>
                                    <div class="poc-description">
                                        External vulnerability database - Manual verification required
                                    </div>
                                    <div class="poc-metrics">
                                        <div class="poc-metric">
                                            &#x1F50E; External Source
                                        </div>
                                    </div>
                                </div>
    """
                
                html_content += """
                            </div>
                        </div>
    """
            else:
                html_content += """
                        <div class="section">
                            <div class="section-header">
                                <div class="section-icon">&#x1F50D;</div>
                                <div class="section-title">Proof of Concepts</div>
                            </div>
                            <div class="no-pocs">
                                <div class="no-pocs-icon">&#x1F6AB;</div>
                                <div class="no-pocs-title">No Public POCs Detected</div>
                                <div class="no-pocs-text">
                                    No proof of concept code was found across GitHub and alternative platforms.<br>
                                    This may indicate the vulnerability is newly disclosed, requires specific conditions,<br>
                                    or exploits are not publicly available.
                                </div>
                            </div>
                        </div>
    """
            references = cve_info.get('references', [])
            if references:
                html_content += """
                        <div class="section">
                            <div class="section-header">
                                <div class="section-icon">&#x1F517;</div>
                                <div class="section-title">References & Resources</div>
                            </div>
                            <div class="references-grid">
    """
                
                for ref in references[:10]:
                    ref_url = safe_html_text(ref.get('url', ''))
                    if ref_url:
                        domain = ref_url.split('/')[2] if len(ref_url.split('/')) > 2 else ref_url
                        html_content += f"""
                                <div class="reference-item">
                                    <a href="{ref_url}" target="_blank" rel="noopener noreferrer">
                                        &#x1F310; {domain}
                                    </a>
                                </div>
    """
                
                html_content += """
                            </div>
                        </div>
    """
            
            html_content += """
                    </div>
                </div>
    """
        html_content += """
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <div class="footer-logo">CVEHawk v2.1</div>
                <div class="footer-text">Enhanced Multi-Platform Vulnerability Intelligence</div>
                <div class="footer-author">Created by @alsh4rfi</div>
            </div>
        </div>
        
        <script>
            // Add smooth scrolling
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });
            
            // Add intersection observer for animations
            const observerOptions = {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            };
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }
                });
            }, observerOptions);
            
            document.querySelectorAll('.cve-card').forEach(el => {
                el.style.opacity = '0';
                el.style.transform = 'translateY(20px)';
                el.style.transition = 'all 0.5s ease-out';
                observer.observe(el);
            });
        </script>
    </body>
    </html>
    """
        
        return html_content

    def search_cve_by_criteria(self, keyword: str = None, year: int = None, 
                            severity: List[str] = None, limit: int = 10) -> List[str]:
        """Search for CVEs by criteria with correct NVD API 2.0 parameters"""
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {}
            if keyword:
                params['keywordSearch'] = keyword
            
            if year:
                params['pubStartDate'] = f"{year}-01-01"
                params['pubEndDate'] = f"{year}-12-31"
            params['resultsPerPage'] = min(limit * 3, 50)
            
            with self.lock:
                print(f"{Colors.BLUE}[INFO]{Colors.RESET} Searching CVEs with criteria...")
                if keyword:
                    print(f"  • Keyword: '{keyword}'")
                if year:
                    print(f"  • Year: {year}")
                if severity:
                    print(f"  • Severity filter: {', '.join(severity)}")
                print(f"  • Requesting up to {limit} results")
            try:
                response = self.session.get(base_url, params=params, timeout=30)
                if response.status_code == 404 and year:
                    print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Trying alternative search approach...")
                    
                    params_no_date = {'keywordSearch': keyword} if keyword else {}
                    params_no_date['resultsPerPage'] = 100
                    
                    response = self.session.get(base_url, params=params_no_date, timeout=30)
                if response.status_code == 403:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} API rate limit exceeded. Please wait a few minutes.")
                    return []
                elif response.status_code == 404:
                    print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No results found. Try broader search terms.")
                    return []
                elif response.status_code != 200:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} API request failed with status {response.status_code}")
                    return []
                data = response.json()
                
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Request failed: {e}")
                return []
            total_results = data.get('totalResults', 0)
            
            if total_results == 0:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No CVEs found matching '{keyword}'")
                return []
            cve_ids = []
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                
                if not cve_id:
                    continue
                if year:
                    try:
                        cve_parts = cve_id.split('-')
                        if len(cve_parts) >= 2:
                            cve_year = int(cve_parts[1])
                            if cve_year != year:
                                continue
                    except:
                        continue
                if severity:
                    metrics = cve.get('metrics', {})
                    cve_severity = 'unknown'
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cve_severity = metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'unknown')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cve_severity = metrics['cvssMetricV30'][0]['cvssData'].get('baseSeverity', 'unknown')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cve_severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'unknown')
                    
                    if cve_severity.lower() not in [s.lower() for s in severity]:
                        continue
                
                cve_ids.append(cve_id)
                
                if len(cve_ids) >= limit:
                    break
            if cve_ids:
                self.display_search_results_with_more(
                    cve_ids, 
                    total_results, 
                    keyword, 
                    year, 
                    severity,
                    limit
                )
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No CVEs matched all filters")
            
            return cve_ids[:limit]
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error: {e}")
            return []

    def display_search_results_with_more(self, cve_ids: List[str], total_results: int, 
                                        keyword: str = None, year: int = None, 
                                        severity: List[str] = None, limit: int = 10):
        """Display search results with 'see more' option"""
        print(f"\n{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}SEARCH RESULTS{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"\n{Colors.BOLD}Search Criteria:{Colors.RESET}")
        if keyword:
            print(f"  • Keyword: {Colors.CYAN}{keyword}{Colors.RESET}")
        if year:
            print(f"  • Year: {Colors.CYAN}{year}{Colors.RESET}")
        if severity:
            print(f"  • Severity: {Colors.CYAN}{', '.join(severity)}{Colors.RESET}")
        print(f"\n{Colors.BOLD}Total Matches Found:{Colors.RESET} {Colors.YELLOW}{total_results}{Colors.RESET} CVEs")
        show_count = min(3, len(cve_ids))  # Show top 3 initially
        print(f"\n{Colors.BOLD}Top {show_count} Results:{Colors.RESET}")
        print(f"{Colors.WHITE}{'─'*50}{Colors.RESET}")
        
        for i, cve_id in enumerate(cve_ids[:show_count], 1):
            if i == 1:
                print(f"  {Colors.YELLOW}★{Colors.RESET} {Colors.BOLD}{Colors.CYAN}{cve_id}{Colors.RESET} {Colors.YELLOW}[TOP MATCH]{Colors.RESET}")
            else:
                print(f"  {i}. {Colors.CYAN}{cve_id}{Colors.RESET}")
        remaining = len(cve_ids) - show_count
        total_remaining = total_results - show_count
        
        if remaining > 0 or total_remaining > show_count:
            print(f"\n{Colors.BOLD}Additional Results:{Colors.RESET}")
            if remaining > 0:
                print(f"  • {Colors.WHITE}{remaining} more CVEs ready to analyze{Colors.RESET}")
                if remaining > 0:
                    preview_count = min(2, remaining)
                    print(f"\n  {Colors.WHITE}Preview of next {preview_count}:{Colors.RESET}")
                    for i, cve_id in enumerate(cve_ids[show_count:show_count+preview_count], show_count+1):
                        print(f"    {i}. {Colors.WHITE}{cve_id}{Colors.RESET}")
            if total_remaining > len(cve_ids):
                print(f"  • {Colors.YELLOW}{total_remaining - len(cve_ids)} more CVEs available in NVD database{Colors.RESET}")
        nvd_url = self.generate_nvd_search_url(keyword, year, severity)
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}📊 View More Options:{Colors.RESET}")
        print(f"{Colors.WHITE}{'─'*50}{Colors.RESET}")
        if len(cve_ids) > show_count:
            print(f"  1. {Colors.GREEN}Analyze all {len(cve_ids)} CVEs:{Colors.RESET}")
            print(f"     {Colors.WHITE}Run: {Colors.CYAN}python cvehawk.py -c {' '.join(cve_ids[:min(5, len(cve_ids))])}{'...' if len(cve_ids) > 5 else ''}{Colors.RESET}")
        print(f"\n  2. {Colors.BLUE}View all {total_results} results in NVD web interface:{Colors.RESET}")
        print(f"     {Colors.CYAN}{nvd_url}{Colors.RESET}")
        print(f"\n  3. {Colors.YELLOW}Refine your search:{Colors.RESET}")
        if not severity:
            print(f"     • Add severity filter: {Colors.WHITE}--severity critical,high{Colors.RESET}")
        if not year:
            print(f"     • Add year filter: {Colors.WHITE}--year 2024{Colors.RESET}")
        print(f"     • Increase limit: {Colors.WHITE}--limit 20{Colors.RESET}")
        if len(cve_ids) > 0:
            print(f"\n  4. {Colors.MAGENTA}Export these results:{Colors.RESET}")
            print(f"     {Colors.WHITE}Add: {Colors.CYAN}--export json,html,csv{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}{'='*70}{Colors.RESET}\n")
        if len(cve_ids) >= 3:
            print(f"{Colors.BOLD}Quick Stats:{Colors.RESET}")
            years = {}
            for cve_id in cve_ids:
                try:
                    year = cve_id.split('-')[1]
                    years[year] = years.get(year, 0) + 1
                except:
                    pass
            
            if years:
                print(f"  • Year distribution: ", end="")
                for y, count in sorted(years.items(), reverse=True)[:3]:
                    print(f"{Colors.CYAN}{y}:{count}{Colors.RESET} ", end="")
                print()
        
        print(f"\n{Colors.BOLD}Returning {len(cve_ids)} CVEs for analysis...{Colors.RESET}\n")

    def generate_nvd_search_url(self, keyword: str = None, year: int = None, 
                            severity: List[str] = None) -> str:
        """Generate a direct link to NVD search results"""
        base_url = "https://nvd.nist.gov/vuln/search/results"
        params = []
        if keyword:
            encoded_keyword = quote(keyword)
            params.append(f"query={encoded_keyword}")
        params.append("form_type=Basic")
        params.append("results_type=overview")
        params.append("search_type=all")
        if year:
            params.append(f"pub_start_date={year}-01-01")
            params.append(f"pub_end_date={year}-12-31")
        if severity:
            for sev in severity:
                if sev.lower() == 'critical':
                    params.append("cvss_version=3&cvss_v3_severity=CRITICAL")
                elif sev.lower() == 'high':
                    params.append("cvss_version=3&cvss_v3_severity=HIGH")
                elif sev.lower() == 'medium':
                    params.append("cvss_version=3&cvss_v3_severity=MEDIUM")
                elif sev.lower() == 'low':
                    params.append("cvss_version=3&cvss_v3_severity=LOW")
        if params:
            url = f"{base_url}?{'&'.join(params)}"
        else:
            url = base_url
        
        return url

    def format_cve_output(self, cve_id: str, cve_data: Dict, poc_results: List[Dict], epss_data: Optional[Dict] = None) -> Dict:
        """Format and print CVE information with proper POC display"""
        from datetime import datetime
        
        try:
            export_data = {
                'cve_id': cve_id,
                'cve_info': cve_data,
                'poc_results': poc_results,
                'epss_data': epss_data,
                'timestamp': datetime.now().isoformat()
            }
            references = cve_data.get('references', [])
            export_data['reference_urls'] = [ref.get('url', '') for ref in references if ref.get('url')]
            
            with self.lock:
                print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.WHITE}CVE ID: {Colors.CYAN}{cve_id}{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
                descriptions = cve_data.get('descriptions', [])
                if descriptions:
                    desc = descriptions[0].get('value', 'No description available')
                    print(f"\n{Colors.BOLD}Description:{Colors.RESET}")
                    print(f"{Colors.WHITE}{desc}{Colors.RESET}")
                published = cve_data.get('published', 'Unknown')
                modified = cve_data.get('lastModified', 'Unknown')
                print(f"\n{Colors.BOLD}Published:{Colors.RESET} {Colors.GREEN}{published[:10] if published != 'Unknown' else 'Unknown'}{Colors.RESET}")
                print(f"{Colors.BOLD}Last Modified:{Colors.RESET} {Colors.YELLOW}{modified[:10] if modified != 'Unknown' else 'Unknown'}{Colors.RESET}")
                if epss_data:
                    epss_score = epss_data.get('epss_score', 0)
                    epss_percentile = epss_data.get('epss_percentile', 0)
                    print(f"\n{Colors.BOLD}{Colors.RED}🎯 EPSS (Exploit Prediction):{Colors.RESET}")
                    print(f"  • Score: {Colors.BOLD}{epss_score:.4f}{Colors.RESET} ({epss_score*100:.2f}% chance of exploit)")
                    print(f"  • Percentile: {Colors.BOLD}{epss_percentile:.1f}%{Colors.RESET} (higher than {epss_percentile:.1f}% of all CVEs)")
                    if epss_score >= 0.7:
                        risk_level = f"{Colors.RED}🔥 CRITICAL RISK{Colors.RESET}"
                    elif epss_score >= 0.3:
                        risk_level = f"{Colors.YELLOW}⚠️  HIGH RISK{Colors.RESET}"
                    elif epss_score >= 0.1:
                        risk_level = f"{Colors.BLUE}📊 MEDIUM RISK{Colors.RESET}"
                    else:
                        risk_level = f"{Colors.GREEN}✅ LOW RISK{Colors.RESET}"
                    
                    print(f"  • Risk Level: {risk_level}")
                    export_data['epss_score'] = epss_score
                    export_data['epss_percentile'] = epss_percentile
                metrics = cve_data.get('metrics', {})
                cvss_score = None
                severity = 'unknown'
                
                if metrics:
                    print(f"\n{Colors.BOLD}CVSS Metrics:{Colors.RESET}")
                    cvss_v31 = metrics.get('cvssMetricV31', [])
                    if cvss_v31:
                        cvss = cvss_v31[0]['cvssData']
                        cvss_score = cvss.get('baseScore', 'N/A')
                        severity = cvss.get('baseSeverity', 'Unknown')
                        severity_color = self.get_severity_color(severity)
                        
                        print(f"  • CVSS v3.1: {Colors.BOLD}{cvss_score}{Colors.RESET} ({severity_color}{severity}{Colors.RESET})")
                        print(f"  • Vector: {Colors.CYAN}{cvss.get('vectorString', 'N/A')}{Colors.RESET}")
                    cvss_v2 = metrics.get('cvssMetricV2', [])
                    if cvss_v2:
                        cvss = cvss_v2[0]['cvssData']
                        if not cvss_score:  # Use v2 if v3.1 not available
                            cvss_score = cvss.get('baseScore', 'N/A')
                            severity = cvss_v2[0].get('baseSeverity', 'Unknown')
                        
                        severity_color = self.get_severity_color(severity)
                        print(f"  • CVSS v2: {Colors.BOLD}{cvss.get('baseScore', 'N/A')}{Colors.RESET} ({severity_color}{severity}{Colors.RESET})")
                export_data['cvss_score'] = cvss_score
                export_data['severity'] = severity
                weaknesses = cve_data.get('weaknesses', [])
                if weaknesses:
                    print(f"\n{Colors.BOLD}Weaknesses (CWE):{Colors.RESET}")
                    for weakness in weaknesses:
                        for desc in weakness.get('description', []):
                            print(f"  • {Colors.MAGENTA}{desc.get('value', 'N/A')}{Colors.RESET}")
                if references:
                    print(f"\n{Colors.BOLD}References:{Colors.RESET}")
                    for ref in references[:5]:  # Show first 5 references
                        url = ref.get('url', '')
                        tags = ', '.join(ref.get('tags', []))
                        print(f"  • {Colors.BLUE}{url}{Colors.RESET}")
                        if tags:
                            print(f"    Tags: {Colors.YELLOW}{tags}{Colors.RESET}")
                print(f"\n{Colors.BOLD}{Colors.RED}🔍 Multi-Platform POC Analysis:{Colors.RESET}")
                print(f"{Colors.RED}{'─'*60}{Colors.RESET}")
                
                if poc_results and len(poc_results) > 0:
                    github_pocs = []
                    alt_platform_pocs = []
                    
                    for poc in poc_results:
                        if poc.get('type') == 'search_link':
                            alt_platform_pocs.append(poc)
                        elif (poc.get('html_url') and 'github.com' in poc.get('html_url', '')) or \
                            poc.get('full_name') or \
                            poc.get('stargazers_count') is not None or \
                            poc.get('source', '').startswith('github'):
                            github_pocs.append(poc)
                        else:
                            alt_platform_pocs.append(poc)
                    if github_pocs:
                        for poc in github_pocs:
                            if 'estimated_commits' not in poc:
                                poc['estimated_commits'] = poc.get('size', 0) // 10
                        github_pocs.sort(key=lambda x: (
                            x.get('stargazers_count', 0) * 1000 +
                            x.get('forks_count', 0) * 100 +
                            x.get('estimated_commits', 0) * 0.1
                        ), reverse=True)
                        
                        print(f"\n{Colors.BOLD}{Colors.CYAN}📦 GitHub Repositories ({len(github_pocs)} found):{Colors.RESET}")
                        print(f"{Colors.WHITE}Ranked by: ⭐ Stars > 🔀 Forks > 📊 Activity{Colors.RESET}\n")
                        
                        for i, poc in enumerate(github_pocs[:15], 1):  # Show up to 15 POCs
                            repo_name = poc.get('full_name', 'Unknown')
                            html_url = poc.get('html_url', 'N/A')
                            description = poc.get('description', 'No description available')
                            stars = poc.get('stargazers_count', 0)
                            forks = poc.get('forks_count', 0)
                            analysis = poc.get('analysis', {})
                            quality_score = analysis.get('quality_score', 0)
                            quality_level = analysis.get('quality_level', 'UNKNOWN')
                            language = analysis.get('language', 'Unknown')
                            last_updated = analysis.get('last_updated', '')
                            if i == 1:
                                rank_emoji = "👑"
                                rank_color = Colors.YELLOW
                                rank_text = "TOP POC"
                            elif i <= 3:
                                rank_emoji = "🥇"
                                rank_color = Colors.CYAN
                                rank_text = f"RANK #{i}"
                            elif i <= 5:
                                rank_emoji = "🥈"
                                rank_color = Colors.BLUE
                                rank_text = f"RANK #{i}"
                            elif i <= 10:
                                rank_emoji = "📌"
                                rank_color = Colors.WHITE
                                rank_text = f"#{i}"
                            else:
                                rank_emoji = ""
                                rank_color = Colors.WHITE
                                rank_text = f"#{i}"
                            if quality_level == 'EXCELLENT':
                                quality_color = Colors.GREEN
                                quality_emoji = "✨"
                            elif quality_level == 'GOOD':
                                quality_color = Colors.BLUE
                                quality_emoji = "✓"
                            elif quality_level == 'FAIR':
                                quality_color = Colors.YELLOW
                                quality_emoji = "•"
                            else:
                                quality_color = Colors.RED
                                quality_emoji = "⚠"
                            print(f"{rank_color}{rank_emoji} {rank_text}{Colors.RESET} - {Colors.CYAN}{repo_name}{Colors.RESET}")
                            print(f"    📍 URL: {Colors.BLUE}{html_url}{Colors.RESET}")
                            print(f"    📊 Metrics: {Colors.YELLOW}⭐ {stars:,} stars{Colors.RESET} | {Colors.GREEN}🔀 {forks:,} forks{Colors.RESET} | {Colors.MAGENTA}💻 {language}{Colors.RESET}")
                            print(f"    🎯 Quality: {quality_color}{quality_emoji} {quality_level}{Colors.RESET} (Score: {quality_score:.0f}/100)")
                            if description:
                                desc_display = description[:100] + '...' if len(description) > 100 else description
                                print(f"    📝 Description: {Colors.WHITE}{desc_display}{Colors.RESET}")
                            if last_updated:
                                try:
                                    updated_date = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                                    days_ago = (datetime.now().astimezone() - updated_date).days
                                    if days_ago == 0:
                                        update_text = "Updated today"
                                    elif days_ago == 1:
                                        update_text = "Updated yesterday"
                                    elif days_ago < 30:
                                        update_text = f"Updated {days_ago} days ago"
                                    elif days_ago < 365:
                                        months = days_ago // 30
                                        update_text = f"Updated {months} month{'s' if months > 1 else ''} ago"
                                    else:
                                        years = days_ago // 365
                                        update_text = f"Updated {years} year{'s' if years > 1 else ''} ago"
                                    print(f"    🕒 {Colors.WHITE}{update_text}{Colors.RESET}")
                                except:
                                    pass
                            if i < min(15, len(github_pocs)):
                                print(f"    {Colors.WHITE}{'·' * 55}{Colors.RESET}")
                    if alt_platform_pocs:
                        print(f"\n{Colors.BOLD}{Colors.MAGENTA}🔗 Alternative Platforms ({len(alt_platform_pocs)} sources):{Colors.RESET}")
                        
                        for i, poc in enumerate(alt_platform_pocs, 1):
                            platform = poc.get('platform', 'Unknown')
                            if not platform or platform == 'Unknown':
                                platform = poc.get('analysis', {}).get('platform', 'External')
                            
                            title = poc.get('title', 'Search results')
                            url = poc.get('url', '')
                            description = poc.get('description', 'Manual verification required')
                            
                            print(f"\n  [{i}] {Colors.MAGENTA}📎 {platform}{Colors.RESET}")
                            print(f"      Title: {Colors.WHITE}{title}{Colors.RESET}")
                            print(f"      URL: {Colors.BLUE}{url}{Colors.RESET}")
                            print(f"      Note: {Colors.YELLOW}{description}{Colors.RESET}")
                    print(f"\n{Colors.BOLD}{Colors.GREEN}📈 POC Summary:{Colors.RESET}")
                    print(f"  • Total POCs found: {Colors.CYAN}{len(poc_results)}{Colors.RESET}")
                    if github_pocs:
                        print(f"  • GitHub repositories: {Colors.CYAN}{len(github_pocs)}{Colors.RESET}")
                        if github_pocs:
                            avg_stars = sum(p.get('stargazers_count', 0) for p in github_pocs) / len(github_pocs)
                            max_stars = max(p.get('stargazers_count', 0) for p in github_pocs)
                            print(f"  • Highest stars: {Colors.YELLOW}⭐ {max_stars:,}{Colors.RESET}")
                            print(f"  • Average stars: {Colors.YELLOW}⭐ {avg_stars:.1f}{Colors.RESET}")
                    if alt_platform_pocs:
                        print(f"  • Alternative sources: {Colors.CYAN}{len(alt_platform_pocs)}{Colors.RESET}")
                        
                else:
                    print(f"{Colors.YELLOW}⚠️  No proof of concepts found across all platforms{Colors.RESET}")
                    print(f"{Colors.YELLOW}This could indicate:{Colors.RESET}")
                    print(f"  • The vulnerability is too new or obscure")
                    print(f"  • POCs exist but are not publicly shared")
                    print(f"  • The vulnerability requires specific conditions to exploit")
                    print(f"  • Search queries need refinement")
                
                print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
                
                return export_data
                    
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Error formatting output: {e}")
            import traceback
            traceback.print_exc()
            return export_data if 'export_data' in locals() else {}

    def process_single_cve(self, cve_id: str) -> Tuple[bool, Optional[Dict]]:
        """Process a single CVE and return success status and export data"""
        try:
            cve_data = self.fetch_cve_details(cve_id)
            if not cve_data:
                with self.lock:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} CVE {cve_id} not found or invalid")
                return False, None
            epss_data = self.fetch_epss_score(cve_id)
            poc_results = self.search_poc_comprehensive(cve_id)
            if poc_results:
                poc_results = self.analyze_poc_quality(poc_results)
            export_data = self.format_cve_output(cve_id, cve_data, poc_results, epss_data)
            return True, export_data
            
        except Exception as e:
            with self.lock:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to process {cve_id}: {e}")
            return False, None

    def lookup_multiple_cves(self, cve_ids: List[str], max_workers: int = 5, export_formats: List[str] = None) -> None:
        """Lookup multiple CVEs using threading with export capability"""
        successful = 0
        failed = 0
        all_export_data = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cve = {executor.submit(self.process_single_cve, cve_id): cve_id 
                           for cve_id in cve_ids}
            for future in as_completed(future_to_cve):
                cve_id = future_to_cve[future]
                try:
                    success, export_data = future.result()
                    if success and export_data:
                        successful += 1
                        all_export_data.append(export_data)
                    else:
                        failed += 1
                except Exception as e:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Exception for {cve_id}: {e}")
                    failed += 1
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}Summary:{Colors.RESET}")
        print(f"  • {Colors.GREEN}Successful: {successful}{Colors.RESET}")
        print(f"  • {Colors.RED}Failed: {failed}{Colors.RESET}")
        print(f"  • {Colors.BLUE}Total: {len(cve_ids)}{Colors.RESET}")
        print(f"  • {Colors.MAGENTA}POCs Found: {sum(len(data.get('poc_results', [])) for data in all_export_data)}{Colors.RESET}")
        if export_formats and all_export_data:
            print(f"\n{Colors.BOLD}Exporting results...{Colors.RESET}")
            for fmt in export_formats:
                try:
                    filepath = self.export_results(all_export_data, fmt)
                    if filepath:
                        print(f"  • {Colors.GREEN}{fmt.upper()} report saved:{Colors.RESET} {filepath}")
                except Exception as e:
                    print(f"  • {Colors.RED}Export failed for {fmt}:{Colors.RESET} {e}")


def create_sample_config():
    """Create a sample configuration file"""
    config_content = """# CVEHawk Configuration File v2.1
api_keys:
  github: "your_github_token_here"  # Optional: for higher GitHub API limits

output:
  format: "detailed"  # detailed, compact
  colors: true

filters:
  min_severity: "none"  # none, low, medium, high, critical

export:
  directory: "./cvehawk_reports"
  default_formats: ["json", "html"]

search:
  max_poc_results: 10
  search_timeout: 30
  alternative_platforms: true
"""
    
    try:
        with open('cvehawk.yaml', 'w') as f:
            f.write(config_content)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Sample config created: cvehawk.yaml")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to create config: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="CVEHawk - Advanced CVE Lookup Tool v2.1 with Enhanced POC Search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cvehawk.py -c CVE-2021-44228
  cvehawk.py -c CVE-2021-44228 CVE-2021-45046 --export json,html
  cvehawk.py -f cve_list.txt -t 10 --export csv
  cvehawk.py --search "remote code execution" --year 2024 --limit 5
  cvehawk.py --search "apache" --severity critical,high --limit 3
  cvehawk.py -c CVE-2021-44228 --config cvehawk.yaml
  cvehawk.py --create-config

Enhanced Features in v2.1:
  • Multi-platform POC search (GitHub repos + code search)
  • Alternative platform integration (Exploit-DB, PacketStorm, Rapid7)
  • Improved POC relevance scoring and quality analysis  
  • Fixed HTML export encoding issues
  • Corrected NVD API 2.0 search parameters
  • Enhanced error handling and user feedback
        """
    )
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('-c', '--cve', nargs='+', help='CVE ID(s) to lookup')
    input_group.add_argument('-f', '--file', help='File containing CVE IDs (one per line)')
    search_group = parser.add_argument_group('Search Options')
    search_group.add_argument('--search', help='Search CVEs by keyword')
    search_group.add_argument('--year', type=int, help='Filter CVEs by year')
    search_group.add_argument('--severity', help='Filter by severity (comma-separated): critical,high,medium,low')
    search_group.add_argument('--limit', type=int, default=10, help='Maximum number of search results (default: 10)')
    process_group = parser.add_argument_group('Processing Options')
    process_group.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    process_group.add_argument('--config', help='Configuration file path (YAML format)')
    export_group = parser.add_argument_group('Export Options')
    export_group.add_argument('--export', help='Export formats (comma-separated): json,html,csv')
    export_group.add_argument('--output', help='Output filename (without extension)')
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument('--create-config', action='store_true', help='Create sample configuration file')
    util_group.add_argument('--version', action='version', version='CVEHawk v2.1')
    
    args = parser.parse_args()
    if args.create_config:
        create_sample_config()
        return
    print_banner()
    cve_tool = CVELookup(args.config)
    cve_ids = []
    if args.search:
        severity_list = None
        if args.severity:
            severity_list = [s.strip() for s in args.severity.split(',')]
            
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Searching for CVEs: '{args.search}'")
        if args.year:
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Year filter: {args.year}")
        if severity_list:
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Severity filter: {', '.join(severity_list)}")
            
        search_results = cve_tool.search_cve_by_criteria(
            keyword=args.search,
            year=args.year,
            severity=severity_list,
            limit=args.limit
        )
        
        if search_results:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(search_results)} CVEs matching criteria")
            for cve in search_results[:5]:  # Show first 5 found CVEs
                print(f"  • {Colors.CYAN}{cve}{Colors.RESET}")
            if len(search_results) > 5:
                print(f"  • ... and {len(search_results) - 5} more")
            cve_ids.extend(search_results)
        else:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No CVEs found matching search criteria")
            return
    if args.cve:
        cve_ids.extend(args.cve)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_cves = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                cve_ids.extend(file_cves)
                print(f"{Colors.GREEN}[INFO]{Colors.RESET} Loaded {len(file_cves)} CVE IDs from file")
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Error reading file: {e}")
            sys.exit(1)
    
    if not cve_ids:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} No CVE IDs provided. Use -c, -f, or --search option.")
        parser.print_help()
        sys.exit(1)
    export_formats = []
    if args.export:
        export_formats = [fmt.strip().lower() for fmt in args.export.split(',')]
        valid_formats = ['json', 'html', 'csv']
        invalid_formats = [fmt for fmt in export_formats if fmt not in valid_formats]
        if invalid_formats:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid export formats: {', '.join(invalid_formats)}")
            print(f"Valid formats: {', '.join(valid_formats)}")
            sys.exit(1)
    normalized_cve_ids = []
    seen = set()
    for cve_id in cve_ids:
        if cve_id.strip():
            normalized = cve_tool.normalize_cve_id(cve_id.strip())
            if normalized not in seen:
                seen.add(normalized)
                normalized_cve_ids.append(normalized)
    
    print(f"{Colors.GREEN}[INFO]{Colors.RESET} Starting enhanced analysis for {len(normalized_cve_ids)} CVE(s)")
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Using {args.threads} threads for parallel processing")
    print(f"{Colors.MAGENTA}[INFO]{Colors.RESET} Multi-platform POC search enabled (GitHub + Alternative platforms)")
    
    if export_formats:
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Export formats: {', '.join(export_formats)}")
    start_time = time.time()
    cve_tool.lookup_multiple_cves(normalized_cve_ids, args.threads, export_formats)
    end_time = time.time()
    
    print(f"\n{Colors.GREEN}[COMPLETED]{Colors.RESET} Total execution time: {end_time - start_time:.2f} seconds")
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} Enhanced CVEHawk v2.1 analysis complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[FATAL ERROR]{Colors.RESET} {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)