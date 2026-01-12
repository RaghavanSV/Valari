import requests
import time
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional
import re

class CVEContextGatherer:
    def __init__(self, db_path="cve_database.db"):
        self.db_path = db_path
        self.nvd_api_key = None  # Optional: Get from https://nvd.nist.gov/developers/request-an-api-key
        self.setup_database()
        
    def setup_database(self):
        """Create database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                vulnerability_type TEXT,
                published_date TEXT,
                last_modified TEXT,
                cvss_v3_score REAL,
                cvss_v3_severity TEXT,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cvss_v2_severity TEXT,
                exploitability_score REAL,
                impact_score REAL,
                cwe_id TEXT,
                cwe_name TEXT,
                gathered_date TEXT,
                raw_data TEXT
            )
        ''')
        
        # Affected software table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS affected_software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_start TEXT,
                version_end TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        ''')
        
        # References table - RENAMED to avoid reserved keyword
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                url TEXT,
                source TEXT,
                tags TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        ''')
        
        # PoC links table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS poc_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                url TEXT,
                source TEXT,
                found_date TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"✓ Database initialized: {self.db_path}")
    
    def set_nvd_api_key(self, api_key: str):
        """Set NVD API key for higher rate limits"""
        self.nvd_api_key = api_key
    
    def fetch_from_nvd(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE data from NVD API"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        params = {'cveId': cve_id}
        
        try:
            print(f"Fetching {cve_id} from NVD...")
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                print(f"✗ No data found for {cve_id}")
                return None
            
            # Rate limiting
            if self.nvd_api_key:
                time.sleep(0.6)  # 50 requests per 30 seconds with API key
            else:
                time.sleep(6)  # 5 requests per 30 seconds without API key
            
            return data['vulnerabilities'][0]['cve']
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error fetching from NVD: {e}")
            return None
    
    def extract_vulnerability_type(self, cve_data: Dict) -> str:
        """Extract vulnerability type from CWE and description"""
        vuln_types = []
        
        # Check CWE
        weaknesses = cve_data.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_name = desc.get('value', '')
                if cwe_name:
                    vuln_types.append(cwe_name)
        
        # Parse description for common vulnerability types
        description = self.get_description(cve_data)
        
        patterns = {
            'Buffer Overflow': r'buffer overflow|buffer over-read|stack overflow',
            'SQL Injection': r'sql injection|sqli',
            'XSS': r'cross-site scripting|xss',
            'RCE': r'remote code execution|rce|arbitrary code execution',
            'Path Traversal': r'path traversal|directory traversal',
            'XXE': r'xml external entity|xxe',
            'SSRF': r'server-side request forgery|ssrf',
            'Deserialization': r'deserialization|unsafe deserialization',
            'Authentication Bypass': r'authentication bypass|auth bypass',
            'Privilege Escalation': r'privilege escalation|escalation of privilege',
            'Memory Corruption': r'memory corruption|use after free|heap overflow',
            'Command Injection': r'command injection|os command injection',
            'Format String': r'format string',
            'Race Condition': r'race condition|toctou'
        }
        
        for vuln_type, pattern in patterns.items():
            if re.search(pattern, description, re.IGNORECASE):
                vuln_types.append(vuln_type)
        
        return ', '.join(set(vuln_types)) if vuln_types else 'Unknown'
    
    def get_description(self, cve_data: Dict) -> str:
        """Extract English description"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def extract_cvss_data(self, cve_data: Dict) -> Dict:
        """Extract CVSS v3 and v2 metrics"""
        cvss_data = {
            'v3_score': None,
            'v3_severity': None,
            'v3_vector': None,
            'v2_score': None,
            'v2_severity': None,
            'exploitability': None,
            'impact': None
        }
        
        metrics = cve_data.get('metrics', {})
        
        # CVSS v3
        if 'cvssMetricV31' in metrics:
            v3_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_data['v3_score'] = v3_data.get('baseScore')
            cvss_data['v3_severity'] = v3_data.get('baseSeverity')
            cvss_data['v3_vector'] = v3_data.get('vectorString')
            cvss_data['exploitability'] = metrics['cvssMetricV31'][0].get('exploitabilityScore')
            cvss_data['impact'] = metrics['cvssMetricV31'][0].get('impactScore')
        elif 'cvssMetricV30' in metrics:
            v3_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_data['v3_score'] = v3_data.get('baseScore')
            cvss_data['v3_severity'] = v3_data.get('baseSeverity')
            cvss_data['v3_vector'] = v3_data.get('vectorString')
            cvss_data['exploitability'] = metrics['cvssMetricV30'][0].get('exploitabilityScore')
            cvss_data['impact'] = metrics['cvssMetricV30'][0].get('impactScore')
        
        # CVSS v2
        if 'cvssMetricV2' in metrics:
            v2_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_data['v2_score'] = v2_data.get('baseScore')
            cvss_data['v2_severity'] = metrics['cvssMetricV2'][0].get('baseSeverity')
        
        return cvss_data
    
    def extract_cwe(self, cve_data: Dict) -> tuple:
        """Extract CWE ID and name"""
        weaknesses = cve_data.get('weaknesses', [])
        if weaknesses:
            for desc in weaknesses[0].get('description', []):
                if desc.get('lang') == 'en':
                    cwe_value = desc.get('value', '')
                    # Extract CWE-XXX format
                    cwe_match = re.search(r'CWE-(\d+)', cwe_value)
                    if cwe_match:
                        return f"CWE-{cwe_match.group(1)}", cwe_value
        return None, None
    
    def extract_affected_software(self, cve_data: Dict) -> List[Dict]:
        """Extract affected software configurations"""
        affected = []
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable', False):
                        cpe_uri = cpe_match.get('criteria', '')
                        # Parse CPE format: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            affected.append({
                                'vendor': parts[3] if len(parts) > 3 else '',
                                'product': parts[4] if len(parts) > 4 else '',
                                'version': parts[5] if len(parts) > 5 else '*',
                                'version_start': cpe_match.get('versionStartIncluding', 
                                                             cpe_match.get('versionStartExcluding', '')),
                                'version_end': cpe_match.get('versionEndIncluding',
                                                           cpe_match.get('versionEndExcluding', ''))
                            })
        
        return affected
    
    def extract_references(self, cve_data: Dict) -> List[Dict]:
        """Extract reference URLs and categorize them"""
        references = []
        refs = cve_data.get('references', [])
        
        for ref in refs:
            url = ref.get('url', '')
            source = ref.get('source', '')
            tags = ', '.join(ref.get('tags', []))
            
            references.append({
                'url': url,
                'source': source,
                'tags': tags
            })
        
        return references
    
    def search_for_pocs(self, cve_id: str) -> List[Dict]:
        """Search for public PoCs on GitHub and Exploit-DB"""
        pocs = []
        
        # Search GitHub
        try:
            print(f"  Searching for PoCs on GitHub...")
            github_url = "https://api.github.com/search/repositories"
            params = {
                'q': f'{cve_id} poc OR exploit',
                'sort': 'stars',
                'order': 'desc',
                'per_page': 5
            }
            
            response = requests.get(github_url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    pocs.append({
                        'url': item['html_url'],
                        'source': 'GitHub',
                        'found_date': datetime.now().isoformat()
                    })
            
            time.sleep(2)  # Rate limiting
            
        except Exception as e:
            print(f"  ✗ Error searching GitHub: {e}")
        
        # Search Exploit-DB (web scraping or API if available)
        try:
            print(f"  Searching Exploit-DB...")
            exploitdb_search = f"https://www.exploit-db.com/search?cve={cve_id}"
            pocs.append({
                'url': exploitdb_search,
                'source': 'Exploit-DB',
                'found_date': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"  ✗ Error with Exploit-DB: {e}")
        
        return pocs
    
    def store_cve_data(self, cve_id: str, cve_data: Dict, pocs: List[Dict]):
        """Store all gathered data in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Extract all data
            description = self.get_description(cve_data)
            vuln_type = self.extract_vulnerability_type(cve_data)
            cvss_data = self.extract_cvss_data(cve_data)
            cwe_id, cwe_name = self.extract_cwe(cve_data)
            affected = self.extract_affected_software(cve_data)
            references = self.extract_references(cve_data)
            
            # Insert main CVE data
            cursor.execute('''
                INSERT OR REPLACE INTO cves VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                vuln_type,
                cve_data.get('published'),
                cve_data.get('lastModified'),
                cvss_data['v3_score'],
                cvss_data['v3_severity'],
                cvss_data['v3_vector'],
                cvss_data['v2_score'],
                cvss_data['v2_severity'],
                cvss_data['exploitability'],
                cvss_data['impact'],
                cwe_id,
                cwe_name,
                datetime.now().isoformat(),
                json.dumps(cve_data)
            ))
            
            # Delete old related data
            cursor.execute('DELETE FROM affected_software WHERE cve_id = ?', (cve_id,))
            cursor.execute('DELETE FROM cve_references WHERE cve_id = ?', (cve_id,))  # CHANGED
            cursor.execute('DELETE FROM poc_links WHERE cve_id = ?', (cve_id,))
            
            # Insert affected software
            for software in affected:
                cursor.execute('''
                    INSERT INTO affected_software (cve_id, vendor, product, version, version_start, version_end)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    software['vendor'],
                    software['product'],
                    software['version'],
                    software['version_start'],
                    software['version_end']
                ))
            
            # Insert references - CHANGED table name
            for ref in references:
                cursor.execute('''
                    INSERT INTO cve_references (cve_id, url, source, tags)
                    VALUES (?, ?, ?, ?)
                ''', (cve_id, ref['url'], ref['source'], ref['tags']))
            
            # Insert PoC links
            for poc in pocs:
                cursor.execute('''
                    INSERT INTO poc_links (cve_id, url, source, found_date)
                    VALUES (?, ?, ?, ?)
                ''', (cve_id, poc['url'], poc['source'], poc['found_date']))
            
            conn.commit()
            print(f"✓ {cve_id} stored successfully")
            
        except Exception as e:
            conn.rollback()
            print(f"✗ Error storing {cve_id}: {e}")
        finally:
            conn.close()
    
    def gather_cve_context(self, cve_id: str) -> bool:
        """Main method to gather all context for a CVE"""
        print(f"\n{'='*60}")
        print(f"Gathering context for {cve_id}")
        print(f"{'='*60}")
        
        # Fetch from NVD
        cve_data = self.fetch_from_nvd(cve_id)
        if not cve_data:
            return False
        
        # Search for PoCs
        pocs = self.search_for_pocs(cve_id)
        
        # Store everything
        self.store_cve_data(cve_id, cve_data, pocs)
        
        return True
    
    def gather_multiple_cves(self, cve_list: List[str]):
        """Gather context for multiple CVEs"""
        successful = 0
        failed = 0
        
        for cve_id in cve_list:
            try:
                if self.gather_cve_context(cve_id):
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                print(f"✗ Error processing {cve_id}: {e}")
                failed += 1
        
        print(f"\n{'='*60}")
        print(f"Summary: {successful} successful, {failed} failed")
        print(f"{'='*60}")
    
    def query_cve(self, cve_id: str) -> Optional[Dict]:
        """Retrieve stored CVE data from database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get main CVE data
        cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
        cve_row = cursor.fetchone()
        
        if not cve_row:
            conn.close()
            return None
        
        # Get affected software
        cursor.execute('SELECT * FROM affected_software WHERE cve_id = ?', (cve_id,))
        affected = [dict(row) for row in cursor.fetchall()]
        
        # Get references - CHANGED table name
        cursor.execute('SELECT * FROM cve_references WHERE cve_id = ?', (cve_id,))
        references = [dict(row) for row in cursor.fetchall()]
        
        # Get PoC links
        cursor.execute('SELECT * FROM poc_links WHERE cve_id = ?', (cve_id,))
        pocs = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'cve': dict(cve_row),
            'affected_software': affected,
            'references': references,
            'pocs': pocs
        }
    
    def print_cve_summary(self, cve_id: str):
        """Print a formatted summary of stored CVE data"""
        data = self.query_cve(cve_id)
        
        if not data:
            print(f"No data found for {cve_id}")
            return
        
        cve = data['cve']
        
        print(f"\n{'='*60}")
        print(f"CVE: {cve['cve_id']}")
        print(f"{'='*60}")
        print(f"Description: {cve['description'][:200]}...")
        print(f"\nVulnerability Type: {cve['vulnerability_type']}")
        print(f"CWE: {cve['cwe_id']} - {cve['cwe_name']}")
        print(f"\nCVSS v3 Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})")
        print(f"Exploitability Score: {cve['exploitability_score']}")
        print(f"Impact Score: {cve['impact_score']}")
        
        print(f"\n--- Affected Software ({len(data['affected_software'])}) ---")
        for software in data['affected_software'][:5]:
            version_info = software['version']
            if software['version_start'] or software['version_end']:
                version_info = f"{software['version_start']} to {software['version_end']}"
            print(f"  • {software['vendor']} {software['product']} {version_info}")
        
        print(f"\n--- References ({len(data['references'])}) ---")
        for ref in data['references'][:5]:
            print(f"  • [{ref['source']}] {ref['url']}")
            if ref['tags']:
                print(f"    Tags: {ref['tags']}")
        
        print(f"\n--- PoC Links ({len(data['pocs'])}) ---")
        for poc in data['pocs']:
            print(f"  • [{poc['source']}] {poc['url']}")
        
        print(f"{'='*60}\n")


# Example usage
if __name__ == "__main__":
    # Initialize gatherer
    gatherer = CVEContextGatherer("cve_exploits.db")
    
    # Optional: Set NVD API key for higher rate limits
    # gatherer.set_nvd_api_key("your-api-key-here")
    
    # Example CVEs to gather
    cve_list = [
        "CVE-2024-3094",  # XZ Utils backdoor
        "CVE-2021-44228",  # Log4Shell
        "CVE-2017-0144",  # EternalBlue
        "CVE-2014-0160",  # Heartbleed
    ]
    
    # Gather context for multiple CVEs
    gatherer.gather_multiple_cves(cve_list)
    
    # Query and display stored data
    print("\n\nRetrieving stored data...")
    for cve_id in cve_list:
        gatherer.print_cve_summary(cve_id)
    
    # Example: Query specific CVE programmatically
    data = gatherer.query_cve("CVE-2021-44228")
    if data:
        print(f"\nLog4Shell CVSS Score: {data['cve']['cvss_v3_score']}")
        print(f"Exploitability: {data['cve']['exploitability_score']}")
        print(f"Number of PoCs found: {len(data['pocs'])}")