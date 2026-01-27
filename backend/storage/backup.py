"""
Backup Module - AWS S3 Failover Storage
========================================

This module provides backup functionality to AWS S3 when the primary
database (Supabase) is unavailable.

WHAT THIS FILE DOES:
1. Connects to AWS S3 using configured credentials
2. Stores alert data as JSON files when database fails
3. Provides disaster recovery capability

WHY THIS EXISTS:
- Database failures happen (network issues, maintenance, outages)
- Security alerts must not be lost during failures
- S3 provides durable storage for failover scenarios
- Enables data recovery after primary DB is restored

USAGE:
    backup_to_s3(alert_data)  # Called automatically on DB failure

REQUIREMENTS:
- AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION in .env
- S3_BUCKET configured with appropriate permissions

Author: AI-SOC Watchdog System
"""

import os
from dotenv import load_dotenv
load_dotenv()
import boto3
import json
from datetime import datetime

# AWS S3 Configuration
S3_BUCKET = os.getenv("S3_BUCKET")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION")

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

def backup_to_s3(alert_data):
    """Backup alert to S3 if database fails"""
    try:
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"alerts/backup_{timestamp}.json"
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=filename,
            Body=json.dumps(alert_data),
            ContentType='application/json'
        )
        
        print(f"[OK] Alert backed up to S3: {filename}")
        return True
    except Exception as e:
        print(f"[ERROR] S3 backup failed: {e}")
        return False


def test_s3_connection():
    """Test S3 connection"""
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET, MaxKeys=1)
        print(f"[OK] S3 connection successful! Bucket: {S3_BUCKET}")
        return True
    except Exception as e:
        print(f"[ERROR] S3 connection failed: {e}")
        return False


if __name__ == '__main__':
    # Test connection
    test_s3_connection()
    
    # Test backup
    test_alert = {
        'alert_name': 'Test Backup',
        'severity': 'high',
        'timestamp': datetime.now().isoformat()
    }
    
    backup_to_s3(test_alert)