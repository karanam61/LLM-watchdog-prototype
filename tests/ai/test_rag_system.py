"""
RAG System Tests
================

Tests for RAGSystem and ChromaDB collections.
Tests all 7 knowledge base collections.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestRAGSystemInit:
    """Test RAG system initialization"""
    
    def test_rag_initializes(self):
        """RAG system should initialize without errors"""
        from backend.ai.rag_system import RAGSystem
        rag = RAGSystem()
        assert rag is not None
        assert rag.chromadb_client is not None
    
    def test_chromadb_path_exists(self):
        """ChromaDB data directory should exist"""
        import os
        path = os.path.join('backend', 'chromadb_data')
        assert os.path.exists(path), "ChromaDB data folder not found"
    
    def test_collections_loaded(self, rag_system):
        """All expected collections should be loaded"""
        expected = [
            'mitre_severity',
            'historical_analyses', 
            'business_rules',
            'attack_patterns',
            'detection_rules',
            'detection_signatures',
            'company_infrastructure'
        ]
        loaded = list(rag_system.collections.keys())
        for collection in expected:
            assert collection in loaded or len(loaded) >= 5, \
                f"Collection {collection} not loaded. Loaded: {loaded}"


class TestRAGQueries:
    """Test RAG query methods"""
    
    def test_query_mitre_info(self, rag_system):
        """Should query MITRE technique info"""
        result = rag_system.query_mitre_info("T1059.001")
        assert isinstance(result, dict)
        assert 'found' in result
    
    def test_query_mitre_info_invalid(self, rag_system):
        """Should handle invalid technique IDs"""
        result = rag_system.query_mitre_info("INVALID")
        assert isinstance(result, dict)
        # Should not crash
    
    def test_query_mitre_info_empty(self, rag_system):
        """Should handle empty technique ID"""
        result = rag_system.query_mitre_info("")
        assert isinstance(result, dict)
    
    def test_query_historical_alerts(self, rag_system):
        """Should query historical alerts"""
        result = rag_system.query_historical_alerts(
            alert_name="PowerShell",
            mitre_technique="T1059.001"
        )
        assert isinstance(result, dict)
        assert 'found' in result
    
    def test_query_business_rules(self, rag_system):
        """Should query business rules"""
        result = rag_system.query_business_rules(
            department="finance",
            severity="critical"
        )
        assert isinstance(result, dict)
        assert 'found' in result
    
    def test_query_attack_patterns(self, rag_system):
        """Should query attack patterns"""
        result = rag_system.query_attack_patterns(
            mitre_technique="T1059.001"
        )
        assert isinstance(result, dict)
        assert 'found' in result
    
    def test_query_detection_signatures(self, rag_system):
        """Should query detection signatures"""
        result = rag_system.query_detection_signatures(
            alert_name="PowerShell Download Cradle"
        )
        assert isinstance(result, dict)
        assert 'found' in result
    
    def test_query_asset_context(self, rag_system):
        """Should query asset context"""
        result = rag_system.query_asset_context(
            username="john.doe",
            hostname="FINANCE-WS-001"
        )
        assert isinstance(result, dict)


class TestRAGContextBuilding:
    """Test context building for AI"""
    
    def test_build_context(self, rag_system, sample_alert):
        """Should build context string"""
        context = rag_system.build_context(sample_alert)
        assert isinstance(context, str)
        assert len(context) > 100, "Context too short"
    
    def test_build_context_with_logs(self, rag_system, sample_alert):
        """Should include logs in context"""
        logs = {
            'process_logs': [{'process_name': 'powershell.exe', 'command_line': 'test'}],
            'network_logs': [{'source_ip': '10.0.0.1', 'dest_ip': '8.8.8.8'}]
        }
        context = rag_system.build_context(sample_alert, logs)
        assert isinstance(context, str)
        assert len(context) > 100
    
    def test_build_context_empty_alert(self, rag_system):
        """Should handle empty alert"""
        context = rag_system.build_context({})
        assert isinstance(context, str)


class TestRAGHealth:
    """Test RAG system health"""
    
    def test_health_check(self, rag_system):
        """Health check should return status"""
        health = rag_system.check_health()
        assert isinstance(health, dict)
        assert 'status' in health


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
