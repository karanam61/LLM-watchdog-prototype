"""
Attack Damage Data - MITRE ATT&CK Damage Scoring
=================================================

This module retrieves damage scores for MITRE ATT&CK techniques from
the database and calculates risk scores for queue routing.

WHAT THIS FILE DOES:
1. Queries mitre_severity table for technique damage scores
2. Caches scores in memory to reduce database queries
3. Applies severity multipliers to calculate risk scores
4. Provides thresholds for queue routing decisions

WHY THIS EXISTS:
- Different attacks cause different levels of damage
- Ransomware (T1486) is more damaging than port scanning
- Risk score determines processing priority
- Enables intelligent queue routing

DAMAGE SCORES (from mitre_severity table):
- T1486 (Ransomware): 90
- T1190 (Exploit): 85
- T1003 (Credential Dump): 80
- T1566 (Phishing): 60
- T1110 (Brute Force): 40

SEVERITY MULTIPLIERS:
- CRITICAL_HIGH: 1.5x
- HIGH: 1.0x
- MEDIUM: 0.7x
- LOW: 0.5x

RISK CALCULATION:
    risk_score = damage_score × severity_multiplier
    If risk_score >= 75 -> Priority Queue

Author: AI-SOC Watchdog System
"""

from backend.storage.database import supabase

# In-memory cache to reduce database queries
_damage_score_cache = {}

# Severity multipliers for risk calculation
SEVERITY_MULTIPLIERS = {
    'CRITICAL_HIGH': 1.5,
    'CRITICAL_MEDIUM': 1.3,
    'HIGH': 1.0,
    'MEDIUM': 0.7,
    'LOW': 0.5
}

# Queue routing thresholds
PRIORITY_QUEUE_THRESHOLD = 75  # Risk score >= 75 goes to priority queue
STANDARD_QUEUE_THRESHOLD = 0   # Everything else goes to standard queue


def get_attack_damage_score(mitre_technique, severity_class=None):
    """
    Get damage score for a MITRE ATT&CK technique from Supabase
    
    Args:
        mitre_technique: MITRE ATT&CK ID (e.g., 'T1486', 'T1566')
        severity_class: Optional severity for unknown technique handling
    
    Returns:
        Tuple of (average_cost, damage_score, description)
    """
    
    # Check cache first (avoid repeated DB queries)
    cache_key = mitre_technique
    if cache_key in _damage_score_cache:
        return _damage_score_cache[cache_key]
    
    try:
        # Query mitre_severity table in Supabase
        result = supabase.table('mitre_severity')\
            .select('average_cost_usd, damage_score, description')\
            .eq('technique_id', mitre_technique)\
            .execute()
        
        if result.data and len(result.data) > 0:
            # Found in database
            row = result.data[0]
            score_tuple = (
                row['average_cost_usd'] or 0,
                row['damage_score'] or 50,
                row['description'] or 'Unknown'
            )
            
            # Cache it for future lookups
            _damage_score_cache[cache_key] = score_tuple
            return score_tuple
        
        else:
            # Unknown technique - use severity-based default
            # Rationale: If severity classifier marked it critical, trust that
            if severity_class in ['CRITICAL_HIGH', 'CRITICAL_MEDIUM']:
                default = (0, 80, 'Unknown Critical Attack Type')
            elif severity_class == 'HIGH':
                default = (0, 65, 'Unknown High-Severity Attack')
            else:
                default = (0, 50, 'Unknown Attack Type')
            
            # Cache the default too (avoid repeated DB queries for unknowns)
            _damage_score_cache[cache_key] = default
            return default
    
    except Exception as e:
        print(f"[ERROR] Error querying attack damage scores: {e}")
        # Fallback to moderate default on database error
        return (0, 50, 'Database Error - Default Score')


def get_severity_multiplier(severity_class):
    """
    Get risk multiplier for severity classification
    
    Args:
        severity_class: Severity string (e.g., 'CRITICAL_HIGH', 'MEDIUM')
    
    Returns:
        Float multiplier (0.5 - 1.5)
    """
    return SEVERITY_MULTIPLIERS.get(severity_class, 1.0)


def calculate_risk_score(mitre_technique, severity_class):
    """
    Calculate total risk score = damage_score [*] severity_multiplier
    
    Args:
        mitre_technique: MITRE ATT&CK ID (e.g., 'T1486')
        severity_class: Severity classification (e.g., 'CRITICAL_HIGH')
    
    Returns:
        Dictionary with risk calculation details
    """
    avg_cost, damage_score, description = get_attack_damage_score(
        mitre_technique, 
        severity_class
    )
    multiplier = get_severity_multiplier(severity_class)
    
    risk_score = damage_score * multiplier
    
    return {
        'risk_score': risk_score,
        'damage_score': damage_score,
        'severity_multiplier': multiplier,
        'avg_cost': avg_cost,
        'description': description,
        'mitre_technique': mitre_technique,
        'severity_class': severity_class
    }


def get_all_techniques_sorted():
    """
    Get all techniques from database sorted by damage score
    
    Returns:
        List of technique dictionaries
    """
    try:
        result = supabase.table('mitre_severity')\
            .select('*')\
            .order('damage_score', desc=True)\
            .execute()
        
        return result.data if result.data else []
    
    except Exception as e:
        print(f"[ERROR] Error fetching all techniques: {e}")
        return []


def clear_cache():
    """
    Clear the in-memory cache (useful for testing or updates)
    """
    global _damage_score_cache
    _damage_score_cache = {}
    print("[OK] Cache cleared")


def get_cache_stats():
    """
    Get statistics about the cache
    
    Returns:
        Dictionary with cache information
    """
    return {
        'cached_techniques': len(_damage_score_cache),
        'cache_keys': list(_damage_score_cache.keys())
    }


if __name__ == '__main__':
    """
    Test the Supabase integration
    """
    print("="*70)
    print("ATTACK DAMAGE DATABASE TEST (Supabase mitre_severity)")
    print("="*70)
    
    # Test 1: Lookup specific techniques
    print("\n[Test 1] Looking up specific attacks from Supabase:")
    
    test_techniques = [
        'T1486',  # Ransomware
        'T1566',  # Phishing
        'T1498',  # DDoS
        'T1110',  # Brute Force
        'T9999'   # Doesn't exist (should use default)
    ]
    
    for technique in test_techniques:
        cost, score, desc = get_attack_damage_score(technique)
        print(f"\n{technique}: {desc}")
        print(f"  Average cost: ${cost:,}")
        print(f"  Damage score: {score}/100")
    
    # Test 2: Calculate risk scores with different severities
    print("\n" + "="*70)
    print("[Test 2] Risk score calculation:")
    
    scenarios = [
        ('T1486', 'CRITICAL_HIGH'),  # Ransomware at critical
        ('T1486', 'MEDIUM'),         # Ransomware at medium (false positive?)
        ('T1498', 'HIGH'),           # DDoS at high
        ('T1110', 'LOW'),            # Brute force at low
    ]
    
    for technique, severity in scenarios:
        result = calculate_risk_score(technique, severity)
        print(f"\n{technique} + {severity}:")
        print(f"  Description: {result['description']}")
        print(f"  Base damage: {result['damage_score']}")
        print(f"  Multiplier: {result['severity_multiplier']}x")
        print(f"  Final risk: {result['risk_score']:.1f}")
        
        queue = 'PRIORITY' if result['risk_score'] >= PRIORITY_QUEUE_THRESHOLD else 'STANDARD'
        print(f"  -> Queue: {queue}")
    
    # Test 3: Cache stats
    print("\n" + "="*70)
    print("[Test 3] Cache statistics:")
    stats = get_cache_stats()
    print(f"  Cached techniques: {stats['cached_techniques']}")
    print(f"  Cache keys: {stats['cache_keys']}")
    
    # Test 4: Get top 10 from database
    print("\n" + "="*70)
    print("[Test 4] Top 10 most damaging attacks from database:")
    
    all_techniques = get_all_techniques_sorted()
    
    if all_techniques:
        print(f"\nTotal techniques in database: {len(all_techniques)}")
        print("\nTop 10:")
        for i, technique in enumerate(all_techniques[:10], 1):
            print(f"{i}. {technique['technique_id']} | Score: {technique['damage_score']:3d} | ${technique.get('average_cost_usd', 0):>10,}")
            print(f"   {technique['technique_name']}: {technique['description']}")
    else:
        print("[ERROR] No techniques found in database")
        print("   Make sure you've populated the mitre_severity table in Supabase")
    
    print("\n" + "="*70)
    print("[OK] SUPABASE INTEGRATION TEST COMPLETE")
    print("="*70)