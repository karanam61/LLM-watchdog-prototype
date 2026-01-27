"""
Dashboard Integration Test
===========================
Tests all dashboards (except Analyst) by:
1. Sending test alert to pipeline
2. Verifying live logging captured operations
3. Verifying RAG endpoints return data
4. Verifying Transparency endpoints return data
5. Verifying Performance metrics endpoint returns data

Run: python tests/test_dashboard_integration.py
"""
import requests
import time
import json
import sys
import os

# Configuration
BASE_URL = "http://localhost:5000"
API_KEY = "secure-ingest-key-123"

def print_status(name, success, details=""):
    icon = "✓" if success else "✗"
    color_code = "\033[92m" if success else "\033[91m"
    reset = "\033[0m"
    print(f"  {color_code}{icon}{reset} {name}: {details}")
    return success

def test_debug_dashboard():
    """Test that live logging API returns operations"""
    print("\n[1/4] Testing Debug Dashboard API...")
    
    try:
        # First, send an alert to generate operations
        alert_data = {
            "alert_name": "Test Dashboard Alert",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.1",
            "description": "PowerShell script execution for dashboard test"
        }
        
        resp = requests.post(
            f"{BASE_URL}/ingest",
            json=alert_data,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        alert_sent = print_status("Sent test alert", resp.status_code == 200, f"Status: {resp.status_code}")
        
        # Wait for operations to be logged
        time.sleep(1)
        
        # Get recent operations
        resp = requests.get(f"{BASE_URL}/api/monitoring/logs/recent?limit=50", timeout=5)
        data = resp.json()
        
        has_operations = 'operations' in data
        operations_count = len(data.get('operations', []))
        
        print_status("API returns 'operations' key", has_operations)
        print_status("Operations logged", operations_count > 0, f"Count: {operations_count}")
        
        # Check categories
        categories = data.get('categories', [])
        print_status("Categories available", len(categories) > 0, f"Categories: {categories}")
        
        return has_operations and operations_count > 0
        
    except Exception as e:
        print_status("Debug Dashboard API", False, str(e))
        return False

def test_rag_dashboard():
    """Test RAG dashboard APIs"""
    print("\n[2/4] Testing RAG Dashboard APIs...")
    
    try:
        # Test RAG stats
        resp = requests.get(f"{BASE_URL}/api/rag/stats", timeout=5)
        stats_ok = print_status("RAG stats endpoint", resp.status_code == 200, f"Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            has_queries = 'total_queries' in data
            print_status("Returns query stats", has_queries, f"Total queries: {data.get('total_queries', 0)}")
        
        # Test collections status
        resp = requests.get(f"{BASE_URL}/api/rag/collections/status", timeout=5)
        collections_ok = print_status("Collections status", resp.status_code == 200)
        
        if resp.status_code == 200:
            data = resp.json()
            collections = data.get('collections', [])
            print_status("Collections returned", len(collections) > 0, f"Count: {len(collections)}")
        
        return stats_ok and collections_ok
        
    except Exception as e:
        print_status("RAG Dashboard API", False, str(e))
        return False

def test_transparency_dashboard():
    """Test Transparency dashboard APIs"""
    print("\n[3/4] Testing Transparency Dashboard APIs...")
    
    try:
        # Test summary endpoint
        resp = requests.get(f"{BASE_URL}/api/transparency/summary", timeout=5)
        summary_ok = print_status("Transparency summary", resp.status_code == 200, f"Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print_status("Returns analysis stats", 'total_analyzed' in data, f"Total: {data.get('total_analyzed', 0)}")
        
        # Get an alert to test proof endpoint
        resp = requests.get(f"{BASE_URL}/alerts", timeout=5)
        if resp.status_code == 200:
            alerts = resp.json().get('alerts', [])
            if alerts:
                alert_id = alerts[0]['id']
                
                resp = requests.get(f"{BASE_URL}/api/transparency/proof/{alert_id}", timeout=5)
                proof_ok = print_status("Transparency proof", resp.status_code == 200, f"Status: {resp.status_code}")
            else:
                proof_ok = print_status("Transparency proof", False, "No alerts available")
        else:
            proof_ok = print_status("Transparency proof", False, f"Status: {resp.status_code}")
        
        return summary_ok and proof_ok
        
    except Exception as e:
        print_status("Transparency Dashboard API", False, str(e))
        return False

def test_performance_dashboard():
    """Test Performance dashboard APIs"""
    print("\n[4/4] Testing Performance Dashboard APIs...")
    
    try:
        # Test metrics endpoint
        resp = requests.get(f"{BASE_URL}/api/monitoring/metrics/dashboard", timeout=5)
        metrics_ok = print_status("Metrics endpoint", resp.status_code == 200, f"Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            has_system = 'system_metrics' in data
            print_status("System metrics present", has_system)
        
        # Test history endpoint
        resp = requests.get(f"{BASE_URL}/api/monitoring/metrics/history?hours=24", timeout=5)
        history_ok = print_status("History endpoint", resp.status_code == 200, f"Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            has_history = 'history' in data
            print_status("History data present", has_history)
        
        return metrics_ok and history_ok
        
    except Exception as e:
        print_status("Performance Dashboard API", False, str(e))
        return False

if __name__ == "__main__":
    print("\n" + "="*70)
    print("AI-SOC DASHBOARD INTEGRATION TEST")
    print("="*70)
    
    debug_ok = test_debug_dashboard()
    rag_ok = test_rag_dashboard()
    transparency_ok = test_transparency_dashboard()
    performance_ok = test_performance_dashboard()
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print_status("Debug Dashboard", debug_ok)
    print_status("RAG Dashboard", rag_ok)
    print_status("Transparency Dashboard", transparency_ok)
    print_status("Performance Dashboard", performance_ok)
    
    all_ok = debug_ok and rag_ok and transparency_ok and performance_ok
    print("\nOverall Status:", "✅ ALL DASHBOARDS OPERATIONAL" if all_ok else "❌ SOME DASHBOARDS FAILED")
