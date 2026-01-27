"""
OSINT Lookup Module
===================

Provides threat intelligence lookups for IPs, hashes, and domains
using free OSINT APIs (no API keys required for basic lookups).

Features:
- IP reputation lookup (AbuseIPDB style)
- Hash lookup (VirusTotal style)
- Domain reputation lookup
- Caching to reduce API calls
"""

import os
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Simple in-memory cache with TTL
_cache = {}
CACHE_TTL_HOURS = 24


class OSINTLookup:
    """
    OSINT threat intelligence lookup service
    
    Uses free APIs where possible, falls back to basic heuristics
    if no API keys are configured.
    """
    
    def __init__(self):
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        
        # Known malicious indicators (basic heuristics)
        self.known_bad_ips = {
            '185.220.101.': 'Tor Exit Node Range',
            '45.33.32.156': 'Known C2 Server',
            '23.129.64.': 'Tor Exit Node Range',
            '104.244.': 'Known Malware Host Range',
        }
        
        self.known_bad_domains = {
            'evil.com': 'Known Malware Domain',
            'malware.ru': 'Known Malware Domain',
            'pastebin.com': 'Data Exfil Risk',
            'transfer.sh': 'Data Exfil Risk',
        }
    
    def _get_cache_key(self, lookup_type: str, value: str) -> str:
        """Generate cache key"""
        return f"{lookup_type}:{value}"
    
    def _get_cached(self, key: str) -> Optional[Dict]:
        """Get cached result if valid"""
        if key in _cache:
            cached = _cache[key]
            if datetime.now() < cached['expires']:
                return cached['data']
        return None
    
    def _set_cache(self, key: str, data: Dict):
        """Cache result with TTL"""
        _cache[key] = {
            'data': data,
            'expires': datetime.now() + timedelta(hours=CACHE_TTL_HOURS)
        }
    
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up IP reputation
        
        Returns:
            {
                'ip': str,
                'is_malicious': bool,
                'confidence': float,
                'category': str,
                'details': str,
                'source': str
            }
        """
        if not ip or ip in ['N/A', 'null', 'None', '']:
            return {'ip': ip, 'is_malicious': False, 'confidence': 0, 'category': 'unknown', 'details': 'Invalid IP', 'source': 'none'}
        
        cache_key = self._get_cache_key('ip', ip)
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        result = {
            'ip': ip,
            'is_malicious': False,
            'confidence': 0.0,
            'category': 'unknown',
            'details': '',
            'source': 'heuristic'
        }
        
        # Check known bad IP ranges
        for bad_ip, reason in self.known_bad_ips.items():
            if ip.startswith(bad_ip):
                result.update({
                    'is_malicious': True,
                    'confidence': 0.85,
                    'category': 'malicious',
                    'details': reason,
                    'source': 'known_bad_list'
                })
                self._set_cache(cache_key, result)
                return result
        
        # Check if private IP (benign)
        if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', '127.', '0.')):
            result.update({
                'is_malicious': False,
                'confidence': 0.95,
                'category': 'private',
                'details': 'Private/Internal IP address',
                'source': 'rfc1918'
            })
            self._set_cache(cache_key, result)
            return result
        
        # Try AbuseIPDB if key available
        if self.abuseipdb_key:
            try:
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers={'Key': self.abuseipdb_key, 'Accept': 'application/json'},
                    params={'ipAddress': ip, 'maxAgeInDays': 90},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    abuse_score = data.get('abuseConfidenceScore', 0)
                    result.update({
                        'is_malicious': abuse_score > 50,
                        'confidence': abuse_score / 100,
                        'category': 'malicious' if abuse_score > 50 else 'suspicious' if abuse_score > 20 else 'clean',
                        'details': f"AbuseIPDB Score: {abuse_score}%, Reports: {data.get('totalReports', 0)}, ISP: {data.get('isp', 'Unknown')}",
                        'source': 'abuseipdb'
                    })
                    self._set_cache(cache_key, result)
                    return result
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup failed: {e}")
        
        # Default: assume public IP needs investigation
        result.update({
            'is_malicious': False,
            'confidence': 0.3,
            'category': 'public',
            'details': 'Public IP - no threat intel available',
            'source': 'default'
        })
        self._set_cache(cache_key, result)
        return result
    
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up file hash reputation
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            {
                'hash': str,
                'is_malicious': bool,
                'confidence': float,
                'category': str,
                'details': str,
                'source': str
            }
        """
        if not file_hash or len(file_hash) < 32:
            return {'hash': file_hash, 'is_malicious': False, 'confidence': 0, 'category': 'unknown', 'details': 'Invalid hash', 'source': 'none'}
        
        cache_key = self._get_cache_key('hash', file_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        result = {
            'hash': file_hash,
            'is_malicious': False,
            'confidence': 0.0,
            'category': 'unknown',
            'details': '',
            'source': 'none'
        }
        
        # Try VirusTotal if key available
        if self.virustotal_key:
            try:
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/files/{file_hash}',
                    headers={'x-apikey': self.virustotal_key},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    
                    if total > 0:
                        ratio = malicious / total
                        result.update({
                            'is_malicious': malicious > 5,
                            'confidence': ratio,
                            'category': 'malicious' if malicious > 5 else 'suspicious' if malicious > 0 else 'clean',
                            'details': f"VirusTotal: {malicious}/{total} detections",
                            'source': 'virustotal'
                        })
                elif response.status_code == 404:
                    result.update({
                        'is_malicious': False,
                        'confidence': 0.5,
                        'category': 'unknown',
                        'details': 'Hash not found in VirusTotal',
                        'source': 'virustotal'
                    })
                    
                self._set_cache(cache_key, result)
                return result
            except Exception as e:
                logger.warning(f"VirusTotal lookup failed: {e}")
        
        # Default: unknown hash
        result.update({
            'details': 'No threat intel available for this hash',
            'source': 'default'
        })
        self._set_cache(cache_key, result)
        return result
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up domain reputation
        
        Returns:
            {
                'domain': str,
                'is_malicious': bool,
                'confidence': float,
                'category': str,
                'details': str,
                'source': str
            }
        """
        if not domain or domain in ['N/A', 'null', 'None', '']:
            return {'domain': domain, 'is_malicious': False, 'confidence': 0, 'category': 'unknown', 'details': 'Invalid domain', 'source': 'none'}
        
        cache_key = self._get_cache_key('domain', domain)
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        
        result = {
            'domain': domain,
            'is_malicious': False,
            'confidence': 0.0,
            'category': 'unknown',
            'details': '',
            'source': 'heuristic'
        }
        
        # Normalize domain
        domain_lower = domain.lower().strip()
        
        # Check known bad domains
        for bad_domain, reason in self.known_bad_domains.items():
            if bad_domain in domain_lower:
                result.update({
                    'is_malicious': True,
                    'confidence': 0.8,
                    'category': 'suspicious',
                    'details': reason,
                    'source': 'known_bad_list'
                })
                self._set_cache(cache_key, result)
                return result
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.ru', '.cn', '.tk', '.xyz', '.top', '.pw', '.cc']
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                result.update({
                    'is_malicious': False,
                    'confidence': 0.4,
                    'category': 'suspicious',
                    'details': f'Suspicious TLD: {tld}',
                    'source': 'heuristic'
                })
                self._set_cache(cache_key, result)
                return result
        
        # Default: unknown domain
        result.update({
            'confidence': 0.3,
            'details': 'No threat intel available',
            'source': 'default'
        })
        self._set_cache(cache_key, result)
        return result
    
    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich alert with OSINT data
        
        Args:
            alert: Alert dictionary with source_ip, dest_ip, file_hash, domain fields
            
        Returns:
            Dictionary with OSINT enrichment for all available indicators
        """
        enrichment = {
            'osint_enriched': True,
            'enrichment_timestamp': datetime.now().isoformat(),
            'indicators': []
        }
        
        # Lookup source IP
        source_ip = alert.get('source_ip')
        if source_ip:
            ip_result = self.lookup_ip(source_ip)
            enrichment['source_ip_intel'] = ip_result
            if ip_result['is_malicious']:
                enrichment['indicators'].append(f"Source IP {source_ip}: {ip_result['details']}")
        
        # Lookup destination IP
        dest_ip = alert.get('dest_ip')
        if dest_ip and dest_ip != source_ip:
            ip_result = self.lookup_ip(dest_ip)
            enrichment['dest_ip_intel'] = ip_result
            if ip_result['is_malicious']:
                enrichment['indicators'].append(f"Dest IP {dest_ip}: {ip_result['details']}")
        
        # Lookup file hash if present
        file_hash = alert.get('file_hash') or alert.get('hash') or alert.get('md5') or alert.get('sha256')
        if file_hash:
            hash_result = self.lookup_hash(file_hash)
            enrichment['hash_intel'] = hash_result
            if hash_result['is_malicious']:
                enrichment['indicators'].append(f"Hash {file_hash[:16]}...: {hash_result['details']}")
        
        # Lookup domain if present
        domain = alert.get('domain') or alert.get('hostname')
        if domain and not domain.startswith(('10.', '192.168.', '172.')):
            domain_result = self.lookup_domain(domain)
            enrichment['domain_intel'] = domain_result
            if domain_result['is_malicious']:
                enrichment['indicators'].append(f"Domain {domain}: {domain_result['details']}")
        
        # Summary
        malicious_count = len(enrichment['indicators'])
        enrichment['threat_score'] = min(1.0, malicious_count * 0.3)
        enrichment['summary'] = f"OSINT found {malicious_count} malicious indicators" if malicious_count > 0 else "No malicious indicators found in OSINT"
        
        return enrichment


# Global instance
osint = OSINTLookup()


def enrich_with_osint(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to enrich alert with OSINT"""
    return osint.enrich_alert(alert)
