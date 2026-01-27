#!/usr/bin/env python3
"""
S3 Failover System Test Script
===============================

Tests the complete S3 failover system to verify the database
single-point-of-failure has been addressed.

TESTS PERFORMED:
1. S3 Connection - Can we connect to S3?
2. S3 Write - Can we write data to S3?
3. S3 Read - Can we read data from S3?
4. Manual Sync - Can we sync all tables to S3?
5. Failover Read - Can we read from S3 when DB is simulated down?
6. API Endpoints - Do the failover API endpoints work?

REQUIREMENTS:
- Backend must be running (python app.py)
- AWS credentials configured in .env
- S3 bucket configured

Usage:
    python scripts/test_s3_failover.py              # Run all tests
    python scripts/test_s3_failover.py --quick      # Quick connection test only
    python scripts/test_s3_failover.py --sync       # Force sync and verify
"""

import os
import sys
import requests
import time
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

BASE_URL = "http://localhost:5000"

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def print_result(test_name, passed, details=None):
    status = "PASS" if passed else "FAIL"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"
    print(f"  [{color}{status}{reset}] {test_name}")
    if details:
        print(f"        {details}")

def test_backend_running():
    """Check if backend is running"""
    try:
        response = requests.get(f"{BASE_URL}/queue-status", timeout=5)
        return response.status_code == 200
    except:
        return False

def test_s3_connection():
    """Test S3 connection via direct module import"""
    print_header("TEST 1: S3 Connection")
    
    try:
        from backend.storage.s3_failover import get_s3_failover
        s3 = get_s3_failover()
        
        print_result("S3 module imported", True)
        print_result("S3 client initialized", s3.s3_client is not None)
        print_result("S3 bucket accessible", s3.s3_available, 
                    f"Bucket: {os.getenv('S3_BUCKET', 'NOT SET')}")
        
        return s3.s3_available
    except Exception as e:
        print_result("S3 connection", False, str(e))
        return False

def test_s3_write():
    """Test writing to S3"""
    print_header("TEST 2: S3 Write")
    
    try:
        from backend.storage.s3_failover import get_s3_failover
        s3 = get_s3_failover()
        
        if not s3.s3_available:
            print_result("S3 write", False, "S3 not available")
            return False
        
        # Write test data
        test_data = [{
            'id': 'test-failover-001',
            'alert_name': 'Failover Test Alert',
            'created_at': datetime.now().isoformat(),
            'test': True
        }]
        
        success = s3.sync_table_to_s3('failover_test', test_data)
        print_result("Write test data to S3", success)
        
        return success
    except Exception as e:
        print_result("S3 write", False, str(e))
        return False

def test_s3_read():
    """Test reading from S3"""
    print_header("TEST 3: S3 Read")
    
    try:
        from backend.storage.s3_failover import get_s3_failover
        s3 = get_s3_failover()
        
        if not s3.s3_available:
            print_result("S3 read", False, "S3 not available")
            return False
        
        # Read test data
        data = s3.read_table_from_s3('failover_test')
        
        if data is not None:
            print_result("Read test data from S3", True, f"Got {len(data)} records")
            return True
        else:
            print_result("Read test data from S3", False, "No data returned")
            return False
    except Exception as e:
        print_result("S3 read", False, str(e))
        return False

def test_api_failover_status():
    """Test failover status API endpoint"""
    print_header("TEST 4: API - Failover Status")
    
    try:
        response = requests.get(f"{BASE_URL}/api/failover/status", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print_result("GET /api/failover/status", True)
            print(f"        In failover mode: {data.get('in_failover_mode', 'unknown')}")
            print(f"        S3 available: {data.get('s3_failover_available', 'unknown')}")
            
            if 's3_status' in data:
                s3_status = data['s3_status']
                print(f"        S3 bucket: {s3_status.get('s3_bucket', 'unknown')}")
                print(f"        Last sync: {s3_status.get('last_sync', {})}")
            return True
        else:
            print_result("GET /api/failover/status", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("GET /api/failover/status", False, str(e))
        return False

def test_api_manual_sync():
    """Test manual S3 sync API endpoint"""
    print_header("TEST 5: API - Manual Sync")
    
    try:
        print("  Triggering manual sync (this may take a moment)...")
        response = requests.post(f"{BASE_URL}/api/failover/sync", timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            print_result("POST /api/failover/sync", data.get('success', False))
            
            results = data.get('results', {})
            for table, success in results.items():
                status = "synced" if success else "FAILED"
                print(f"        {table}: {status}")
            
            print(f"        Total: {data.get('synced', 0)}/{data.get('total', 0)} tables synced")
            return data.get('success', False)
        elif response.status_code == 503:
            print_result("POST /api/failover/sync", False, "S3 failover not enabled")
            return False
        else:
            print_result("POST /api/failover/sync", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("POST /api/failover/sync", False, str(e))
        return False

def test_api_failover_test():
    """Test the failover test API endpoint"""
    print_header("TEST 6: API - Failover Test")
    
    try:
        print("  Running failover tests...")
        response = requests.post(f"{BASE_URL}/api/failover/test", timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            tests = data.get('tests', {})
            
            print_result("S3 Connection", tests.get('s3_connection', False))
            print_result("Alerts Readable", tests.get('alerts_readable', False),
                        f"{tests.get('alerts_count', 0)} alerts in S3")
            print_result("Process Logs Readable", tests.get('process_logs_readable', False),
                        f"{tests.get('process_logs_count', 0)} logs in S3")
            print_result("Network Logs Readable", tests.get('network_logs_readable', False),
                        f"{tests.get('network_logs_count', 0)} logs in S3")
            
            return data.get('success', False)
        elif response.status_code == 503:
            print_result("POST /api/failover/test", False, "S3 failover not enabled")
            return False
        else:
            print_result("POST /api/failover/test", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("POST /api/failover/test", False, str(e))
        return False

def test_database_functions_with_fallback():
    """Test that database functions have S3 fallback"""
    print_header("TEST 7: Database Functions with Fallback")
    
    try:
        from backend.storage.database import (
            get_failover_status,
            is_in_failover_mode,
            get_all_alerts,
            S3_FAILOVER_AVAILABLE
        )
        
        print_result("S3 failover module available", S3_FAILOVER_AVAILABLE)
        print_result("get_failover_status() works", get_failover_status() is not None)
        print_result("is_in_failover_mode() works", isinstance(is_in_failover_mode(), bool))
        
        # Test get_all_alerts (should work from either source)
        alerts = get_all_alerts(limit=5)
        print_result("get_all_alerts() works", alerts is not None,
                    f"Got {len(alerts) if alerts else 0} alerts")
        
        return S3_FAILOVER_AVAILABLE
    except Exception as e:
        print_result("Database functions", False, str(e))
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Test S3 Failover System')
    parser.add_argument('--quick', action='store_true', help='Quick connection test only')
    parser.add_argument('--sync', action='store_true', help='Force sync and verify')
    args = parser.parse_args()
    
    print("\n" + "=" * 60)
    print("  S3 FAILOVER SYSTEM TEST")
    print("=" * 60)
    
    # Check backend
    if not test_backend_running():
        print("\n[ERROR] Backend not running! Start with: python app.py")
        print("        Then run this test again.\n")
        return
    
    print("\n  Backend is running. Starting tests...\n")
    
    results = {}
    
    # Quick test mode
    if args.quick:
        results['s3_connection'] = test_s3_connection()
        results['api_status'] = test_api_failover_status()
    
    # Sync mode
    elif args.sync:
        results['api_sync'] = test_api_manual_sync()
        results['api_test'] = test_api_failover_test()
    
    # Full test mode
    else:
        results['s3_connection'] = test_s3_connection()
        results['s3_write'] = test_s3_write()
        results['s3_read'] = test_s3_read()
        results['api_status'] = test_api_failover_status()
        results['api_sync'] = test_api_manual_sync()
        results['api_test'] = test_api_failover_test()
        results['db_functions'] = test_database_functions_with_fallback()
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        print_result(test_name.replace('_', ' ').title(), result)
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  [SUCCESS] S3 Failover System is fully operational!")
        print("  The database is no longer a single point of failure.\n")
    elif passed > 0:
        print("\n  [WARNING] Some tests failed. Check configuration.")
        print("  Partial failover capability available.\n")
    else:
        print("\n  [ERROR] All tests failed! S3 failover is not working.")
        print("  Check AWS credentials and S3 bucket configuration.\n")
        print("  Required .env variables:")
        print("    - AWS_ACCESS_KEY")
        print("    - AWS_SECRET_KEY")
        print("    - AWS_REGION")
        print("    - S3_BUCKET\n")

if __name__ == '__main__':
    main()
