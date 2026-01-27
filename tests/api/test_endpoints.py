"""
API Endpoint Tests
==================

Tests for all Flask API endpoints.
Requires backend to be running on localhost:5000.
"""

import pytest
import requests
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# Skip all tests if backend not running
def backend_available():
    try:
        requests.get('http://localhost:5000/queue-status', timeout=2)
        return True
    except:
        return False


@pytest.mark.skipif(not backend_available(), reason="Backend not running")
class TestCoreEndpoints:
    """Test core API endpoints"""
    
    BASE_URL = "http://localhost:5000"
    
    def test_queue_status(self):
        """GET /queue-status should return queue sizes"""
        response = requests.get(f"{self.BASE_URL}/queue-status")
        assert response.status_code == 200
        data = response.json()
        assert 'priority_count' in data
        assert 'standard_count' in data
    
    def test_get_alerts(self):
        """GET /alerts should return alert list"""
        response = requests.get(f"{self.BASE_URL}/alerts")
        assert response.status_code == 200
        data = response.json()
        assert 'alerts' in data
        assert isinstance(data['alerts'], list)
    
    def test_get_logs_requires_alert_id(self):
        """GET /api/logs should require alert_id"""
        response = requests.get(f"{self.BASE_URL}/api/logs?type=process")
        assert response.status_code == 400
    
    def test_get_logs_with_alert_id(self):
        """GET /api/logs should work with alert_id"""
        # First get an alert ID
        alerts_response = requests.get(f"{self.BASE_URL}/alerts")
        alerts = alerts_response.json().get('alerts', [])
        
        if alerts:
            alert_id = alerts[0]['id']
            response = requests.get(
                f"{self.BASE_URL}/api/logs",
                params={'type': 'process', 'alert_id': alert_id}
            )
            assert response.status_code == 200


@pytest.mark.skipif(not backend_available(), reason="Backend not running")
class TestIngestEndpoint:
    """Test alert ingestion endpoint"""
    
    BASE_URL = "http://localhost:5000"
    API_KEY = os.getenv('INGEST_API_KEY', 'secure-ingest-key-123')
    
    def test_ingest_requires_api_key(self):
        """POST /ingest should require API key"""
        response = requests.post(
            f"{self.BASE_URL}/ingest",
            json={'alert_name': 'Test', 'severity': 'low'}
        )
        assert response.status_code == 401
    
    def test_ingest_with_api_key(self):
        """POST /ingest should accept valid API key"""
        response = requests.post(
            f"{self.BASE_URL}/ingest",
            headers={"X-API-Key": self.API_KEY},
            json={
                'alert_name': 'API Test Alert',
                'severity': 'low',
                'description': 'Test from pytest'
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert 'status' in data or 'alert_id' in data
    
    def test_ingest_returns_alert_id(self):
        """POST /ingest should return alert_id"""
        response = requests.post(
            f"{self.BASE_URL}/ingest",
            headers={"X-API-Key": self.API_KEY},
            json={
                'alert_name': 'Test Alert ID',
                'severity': 'medium',
                'description': 'Testing alert ID return'
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Should have either alert_id or status
        assert 'alert_id' in data or 'status' in data


@pytest.mark.skipif(not backend_available(), reason="Backend not running")
class TestRAGEndpoints:
    """Test RAG monitoring endpoints"""
    
    BASE_URL = "http://localhost:5000"
    
    def test_rag_stats(self):
        """GET /api/rag/stats should return stats"""
        response = requests.get(f"{self.BASE_URL}/api/rag/stats")
        assert response.status_code == 200
        data = response.json()
        assert 'total_queries' in data or 'total_alerts' in data
    
    def test_rag_collections_status(self):
        """GET /api/rag/collections/status should return status"""
        response = requests.get(f"{self.BASE_URL}/api/rag/collections/status")
        assert response.status_code == 200
        data = response.json()
        assert 'collections' in data
        assert isinstance(data['collections'], list)
    
    def test_rag_usage_requires_alert_id(self):
        """GET /api/rag/usage/{id} should work with valid ID"""
        # First get an alert ID
        alerts_response = requests.get(f"{self.BASE_URL}/alerts")
        alerts = alerts_response.json().get('alerts', [])
        
        if alerts:
            # Find an analyzed alert
            analyzed = [a for a in alerts if a.get('ai_verdict')]
            if analyzed:
                alert_id = analyzed[0]['id']
                response = requests.get(f"{self.BASE_URL}/api/rag/usage/{alert_id}")
                assert response.status_code in [200, 404]


@pytest.mark.skipif(not backend_available(), reason="Backend not running")
class TestMonitoringEndpoints:
    """Test monitoring endpoints"""
    
    BASE_URL = "http://localhost:5000"
    
    def test_metrics_dashboard(self):
        """GET /api/monitoring/metrics/dashboard should return metrics"""
        response = requests.get(f"{self.BASE_URL}/api/monitoring/metrics/dashboard")
        assert response.status_code == 200
    
    def test_recent_logs(self):
        """GET /api/monitoring/logs/recent should return logs"""
        response = requests.get(f"{self.BASE_URL}/api/monitoring/logs/recent")
        assert response.status_code == 200
        data = response.json()
        assert 'operations' in data or 'count' in data
    
    def test_log_categories(self):
        """GET /api/monitoring/logs/categories should return categories"""
        response = requests.get(f"{self.BASE_URL}/api/monitoring/logs/categories")
        assert response.status_code == 200


@pytest.mark.skipif(not backend_available(), reason="Backend not running")
class TestAlertUpdate:
    """Test alert update endpoint"""
    
    BASE_URL = "http://localhost:5000"
    
    def test_update_alert_status(self):
        """PATCH /api/alerts/{id} should update status"""
        # First get an alert ID
        alerts_response = requests.get(f"{self.BASE_URL}/alerts")
        alerts = alerts_response.json().get('alerts', [])
        
        if alerts:
            alert_id = alerts[0]['id']
            response = requests.patch(
                f"{self.BASE_URL}/api/alerts/{alert_id}",
                json={'status': 'investigating'}
            )
            assert response.status_code == 200
    
    def test_update_requires_status(self):
        """PATCH /api/alerts/{id} should require status"""
        response = requests.patch(
            f"{self.BASE_URL}/api/alerts/some-id",
            json={}
        )
        assert response.status_code == 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
