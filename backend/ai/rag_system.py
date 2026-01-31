"""
RAG System - Retrieval-Augmented Generation for Alert Analysis
===============================================================

Queries ChromaDB collections to provide comprehensive context for AI-powered
alert triage. Combines MITRE data, historical incidents, business rules,
attack patterns, detection signatures, and asset context.

Architecture:
    Alert -> RAG queries 7 collections -> Build context -> Send to Claude API

Collections:
    1. mitre_severity - Technique severity and business impact
    2. historical_analyses - Past alerts and outcomes
    3. business_rules - Organizational priorities
    4. attack_patterns - Detection indicators
    5. detection_rules - SIEM correlation rules
    6. detection_signatures - Regex/behavioral patterns
    7. company_infrastructure - Asset context (tokenized)

Author: AI-SOC Watchdog System
"""

import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import chromadb


import logging

logger = logging.getLogger(__name__)

class RAGSystem:
    """
    Semantic search system for security alert context enrichment.
    
    Provides relevant historical data, business rules, and technical
    information to enhance AI-powered alert analysis.
    """
    
    def __init__(self, chromadb_path: Optional[str] = None):
        """
        Initialize RAG system with ChromaDB client.
        
        Args:
            chromadb_path: Path to ChromaDB storage. 
                          Defaults to backend/chromadb_data
        """
        # Default path: backend/chromadb_data
        if chromadb_path is None:
            backend_dir = Path(__file__).parent.parent
            chromadb_path = os.path.join(str(backend_dir), "chromadb_data")
        
        logger.info(f"[RAG] Initializing ChromaDB from: {chromadb_path}")
        
        # Connect to ChromaDB
        self.chromadb_client = chromadb.PersistentClient(path=chromadb_path)
        
        # Store collections
        self.collections = {}
        self._load_collections()
        
        logger.info(f"[RAG] Loaded {len(self.collections)} collections")
    
    def _load_collections(self):
        """Load all ChromaDB collections."""
        collection_names = [
            "mitre_severity",
            "historical_analyses",
            "business_rules",
            "attack_patterns",
            "detection_rules",
            "detection_signatures",
            "company_infrastructure"
        ]
        
        for name in collection_names:
            try:
                self.collections[name] = self.chromadb_client.get_collection(name)
                logger.debug(f"  [OK] Loaded: {name}")
            except Exception as e:
                logger.warning(f"  [WARNING]  Could not load '{name}': {e}")
                
    def check_health(self) -> dict:
        """
        Check connection to ChromaDB.
        Returns:
            dict: { 'status': 'healthy'|'unhealthy', 'latency_ms': float }
        """
        import time
        start = time.time()
        try:
            # Simple heartbeat check (listing collections is cheap)
            self.chromadb_client.list_collections()
            return {
                'status': 'healthy',
                'latency_ms': (time.time() - start) * 1000
            }
        except Exception as e:
            logger.error(f"[RAG] Health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    # =========================================================================
    # QUERY METHODS (One per collection)
    # =========================================================================
    
    def query_mitre_info(self, technique_id: str) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK technique information and business impact.
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1059.001")
        
        Returns:
            Dict with: found (bool), content (str), metadata (dict)
        """
        if "mitre_severity" not in self.collections:
            return {"found": False, "error": "MITRE collection not loaded"}
        
        if not technique_id:
            return {"found": False, "content": ""}
        
        try:
            results = self.collections["mitre_severity"].query(
                query_texts=[f"MITRE Technique {technique_id}"],
                n_results=1
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                print(f"      [AI TRACE] RAG (MITRE): Found info for {technique_id}")
                return {
                    "found": True,
                    "content": results['documents'][0][0],
                    "metadata": results['metadatas'][0][0] if results['metadatas'] else {}
                }
            else:
                print(f"      [AI TRACE] RAG (MITRE): No info for {technique_id}")
                return {"found": False, "content": ""}
        
        except Exception as e:
            print(f"      [AI TRACE] RAG (MITRE) Error: {e}")
            logger.error(f"[RAG] Error querying MITRE: {e}")
            return {"found": False, "error": str(e)}
    
    def query_historical_alerts(
        self, 
        alert_name: str = "", 
        mitre_technique: str = "", 
        department: str = "",
        n_results: int = 3
    ) -> Dict[str, Any]:
        """
        Get similar historical alerts and their outcomes.
        
        Args:
            alert_name: Name/type of alert
            mitre_technique: MITRE technique ID
            department: Department affected
            n_results: Number of results to return
        
        Returns:
            Dict with: found (bool), count (int), analyses (list)
        """
        if "historical_analyses" not in self.collections:
            return {"found": False, "error": "Historical analyses not loaded"}
        
        # Build search query
        query_parts = []
        if alert_name:
            query_parts.append(alert_name)
        if mitre_technique:
            query_parts.append(mitre_technique)
        if department:
            query_parts.append(f"{department} department")
        
        query_text = " ".join(query_parts) if query_parts else "security alert"
        
        try:
            results = self.collections["historical_analyses"].query(
                query_texts=[query_text],
                n_results=n_results
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                count = len(results['documents'][0])
                print(f"      [AI TRACE] RAG (History): Found {count} similar alerts")
                return {
                    "found": True,
                    "count": count,
                    "analyses": results['documents'][0],
                    "metadata": results['metadatas'][0] if results['metadatas'] else []
                }
            else:
                print("      [AI TRACE] RAG (History): No matches found")
                return {"found": False, "analyses": []}
        
        except Exception as e:
            print(f"      [AI TRACE] RAG (History) Error: {e}")
            logger.error(f"[RAG] Error querying history: {e}")
            return {"found": False, "error": str(e)}
    
    def query_business_rules(
        self,
        department: str = "",
        severity: str = "",
        n_results: int = 3
    ) -> Dict[str, Any]:
        """
        Get organizational priorities and business context.
        
        Args:
            department: Department name
            severity: Alert severity
            n_results: Number of results to return
        
        Returns:
            Dict with: found (bool), count (int), rules (list)
        """
        if "business_rules" not in self.collections:
            return {"found": False, "error": "Business rules not loaded"}
        
        query_parts = []
        if department:
            query_parts.append(f"{department} department")
        if severity:
            query_parts.append(f"{severity} severity")
        query_parts.append("priority escalation rules")
        
        query_text = " ".join(query_parts)
        
        try:
            results = self.collections["business_rules"].query(
                query_texts=[query_text],
                n_results=n_results
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                return {
                    "found": True,
                    "count": len(results['documents'][0]),
                    "rules": results['documents'][0],
                    "metadata": results['metadatas'][0] if results['metadatas'] else []
                }
            else:
                return {"found": False, "rules": []}
        
        except Exception as e:
            logger.error(f"[RAG] Error querying business rules: {e}")
            return {"found": False, "error": str(e)}
    
    def query_attack_patterns(
        self,
        mitre_technique: str = "",
        attack_type: str = "",
        n_results: int = 2
    ) -> Dict[str, Any]:
        """
        Get attack patterns and detection indicators.
        
        Args:
            mitre_technique: MITRE technique ID
            attack_type: Type of attack (e.g., "PowerShell", "LOLBin")
            n_results: Number of results to return
        
        Returns:
            Dict with: found (bool), count (int), patterns (list)
        """
        if "attack_patterns" not in self.collections:
            return {"found": False, "error": "Attack patterns not loaded"}
        
        query_parts = []
        if mitre_technique:
            query_parts.append(mitre_technique)
        if attack_type:
            query_parts.append(attack_type)
        
        query_text = " ".join(query_parts) if query_parts else "attack pattern"
        
        try:
            results = self.collections["attack_patterns"].query(
                query_texts=[query_text],
                n_results=n_results
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                return {
                    "found": True,
                    "count": len(results['documents'][0]),
                    "patterns": results['documents'][0],
                    "metadata": results['metadatas'][0] if results['metadatas'] else []
                }
            else:
                return {"found": False, "patterns": []}
        
        except Exception as e:
            logger.error(f"[RAG] Error querying attack patterns: {e}")
            return {"found": False, "error": str(e)}
    
    def query_detection_rules(
        self,
        alert_name: str = "",
        n_results: int = 2
    ) -> Dict[str, Any]:
        """
        Get detection rules that triggered this alert type.
        
        Args:
            alert_name: Name of the alert
            n_results: Number of results to return
        
        Returns:
            Dict with: found (bool), rules (list)
        """
        if "detection_rules" not in self.collections:
            return {"found": False, "error": "Detection rules not loaded"}
        
        if not alert_name:
            return {"found": False, "rules": []}
        
        try:
            results = self.collections["detection_rules"].query(
                query_texts=[alert_name],
                n_results=n_results
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                return {
                    "found": True,
                    "count": len(results['documents'][0]),
                    "rules": results['documents'][0]
                }
            else:
                return {"found": False, "rules": []}
        
        except Exception as e:
            logger.error(f"[RAG] Error querying detection rules: {e}")
            return {"found": False, "error": str(e)}
    
    def query_detection_signatures(
        self,
        alert_name: str = "",
        n_results: int = 3
    ) -> Dict[str, Any]:
        """
        Get signature patterns that matched.
        
        Args:
            alert_name: Name of the alert
            n_results: Number of results to return
        
        Returns:
            Dict with: found (bool), signatures (list)
        """
        if "detection_signatures" not in self.collections:
            return {"found": False, "error": "Detection signatures not loaded"}
        
        if not alert_name:
            return {"found": False, "signatures": []}
        
        # Extract key terms from alert name for better matching
        search_terms = alert_name.lower()
        
        try:
            results = self.collections["detection_signatures"].query(
                query_texts=[search_terms],
                n_results=n_results
            )
            
            if results and results['documents'] and len(results['documents'][0]) > 0:
                return {
                    "found": True,
                    "count": len(results['documents'][0]),
                    "signatures": results['documents'][0]
                }
            else:
                return {"found": False, "signatures": []}
        
        except Exception as e:
            logger.error(f"[RAG] Error querying signatures: {e}")
            return {"found": False, "error": str(e)}
    
    def query_asset_context(
        self,
        username: str = "",
        hostname: str = "",
        n_results: int = 1
    ) -> Dict[str, Any]:
        """
        Get context about affected user and host (tokenized assets).
        
        Args:
            username: Tokenized username (e.g., "USER-7bc3e1f5")
            hostname: Tokenized hostname (e.g., "HOST-8d4f6e2a")
            n_results: Number of results per query
        
        Returns:
            Dict with: user_context (str), host_context (str)
        """
        if "company_infrastructure" not in self.collections:
            return {"found": False, "error": "Infrastructure not loaded"}
        
        context = {"found": False}
        
        # Query for user info
        if username:
            try:
                user_results = self.collections["company_infrastructure"].query(
                    query_texts=[f"employee {username}"],
                    n_results=n_results,
                    where={"entity_type": "employee"}
                )
                
                if user_results and user_results['documents'] and len(user_results['documents'][0]) > 0:
                    context["user_context"] = user_results['documents'][0][0]
                    context["found"] = True
            except Exception as e:
                logger.error(f"[RAG] Error querying user context: {e}")
        
        # Query for host info
        if hostname:
            try:
                host_results = self.collections["company_infrastructure"].query(
                    query_texts=[f"server {hostname}"],
                    n_results=n_results,
                    where={"entity_type": "server"}
                )
                
                if host_results and host_results['documents'] and len(host_results['documents'][0]) > 0:
                    context["host_context"] = host_results['documents'][0][0]
                    context["found"] = True
            except Exception as e:
                print(f"      [AI TRACE] RAG (Asset) Error: {e}")
                logger.error(f"[RAG] Error querying host context: {e}")
        
        if context.get("found"):
            print("      [AI TRACE] RAG (Asset): Asset context retrieved")
        return context
    
    # =========================================================================
    # MAIN CONTEXT BUILDING FUNCTION
    # =========================================================================
    
    def build_context(
        self,
        alert: Dict[str, Any],
        logs: Optional[Dict[str, List]] = None
    ) -> str:
        """
        Build comprehensive context by querying all collections PARALLELIZED.
        """
        import concurrent.futures
        
        context_parts = []
        
        # Header
        context_parts.append("=" * 70)
        context_parts.append("ALERT ANALYSIS CONTEXT (from RAG)")
        context_parts.append("=" * 70)
        
        print("\n[AI TRACE] [*] Building Context for AI Analysis (Parallel)...")
        
        # Extract metadata
        department = self._extract_department(alert)
        attack_type = self._extract_attack_type(alert.get('alert_name', ''))
        
        # Define query functions
        def get_mitre():
            if alert.get('mitre_technique'):
                return self.query_mitre_info(alert['mitre_technique'])
            return {"found": False}

        def get_history():
            return self.query_historical_alerts(
                alert_name=alert.get('alert_name', ''),
                mitre_technique=alert.get('mitre_technique', ''),
                department=department,
                n_results=2
            )

        def get_business():
            return self.query_business_rules(
                department=department,
                severity=alert.get('severity', ''),
                n_results=2
            )

        def get_patterns():
            return self.query_attack_patterns(
                mitre_technique=alert.get('mitre_technique', ''),
                attack_type=attack_type,
                n_results=2
            )

        def get_detection():
            return self.query_detection_rules(
                alert_name=alert.get('alert_name', ''),
                n_results=1
            )

        def get_signatures():
            return self.query_detection_signatures(
                alert_name=alert.get('alert_name', ''),
                n_results=3
            )

        def get_asset():
            return self.query_asset_context(
                username=alert.get('username', ''),
                hostname=alert.get('hostname', '')
            )

        # Execute in parallel
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            future_map = {
                executor.submit(get_mitre): 'mitre',
                executor.submit(get_history): 'history',
                executor.submit(get_business): 'business',
                executor.submit(get_patterns): 'patterns',
                executor.submit(get_detection): 'detection',
                executor.submit(get_signatures): 'signatures',
                executor.submit(get_asset): 'asset'
            }
            
            for future in concurrent.futures.as_completed(future_map):
                key = future_map[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    logger.error(f"[RAG] Parallel query failed for {key}: {e}")
                    results[key] = {"found": False}

        # ------------------------------------------------------------------
        # Assemble Context (Deterministic Order)
        # ------------------------------------------------------------------

        # 1. MITRE Technique Info
        mitre_info = results.get('mitre')
        if mitre_info and mitre_info.get('found'):
            context_parts.append("\n## 1. MITRE TECHNIQUE INFORMATION:")
            context_parts.append(mitre_info['content'][:800])

        # 2. Historical Similar Alerts
        history = results.get('history')
        if history and history.get('found') and history['count'] > 0:
            context_parts.append("\n## 2. HISTORICAL SIMILAR INCIDENTS:")
            context_parts.append(f"Found {history['count']} similar past alerts:\n")
            for idx, analysis in enumerate(history['analyses'][:2], 1):
                context_parts.append(f"\n### Past Incident {idx}:")
                truncated = analysis[:600] + "..." if len(analysis) > 600 else analysis
                context_parts.append(truncated)

        # 3. Business Rules & Priorities
        business = results.get('business')
        if business and business.get('found') and business['count'] > 0:
            context_parts.append("\n## 3. BUSINESS CONTEXT & PRIORITIES:")
            for rule in business['rules'][:2]:
                context_parts.append(rule[:500])

        # 4. Attack Patterns
        patterns = results.get('patterns')
        if patterns and patterns.get('found') and patterns['count'] > 0:
            context_parts.append("\n## 4. ATTACK PATTERNS & INDICATORS:")
            for pattern in patterns['patterns'][:2]:
                context_parts.append(pattern[:500])

        # 5. Detection Rules
        detection = results.get('detection')
        if detection and detection.get('found') and detection['count'] > 0:
            context_parts.append("\n## 5. DETECTION RULE THAT TRIGGERED:")
            context_parts.append(detection['rules'][0][:500])

        # 6. Detection Signatures
        signatures = results.get('signatures')
        if signatures and signatures.get('found') and signatures['count'] > 0:
            context_parts.append("\n## 6. SIGNATURE PATTERNS MATCHED:")
            for sig in signatures['signatures'][:3]:
                context_parts.append(sig[:400])

        # 7. Asset Context
        asset = results.get('asset')
        if asset and asset.get('found'):
            context_parts.append("\n## 7. ASSET CONTEXT:")
            if asset.get('user_context'):
                context_parts.append("User Information:")
                context_parts.append(asset['user_context'][:400])
            if asset.get('host_context'):
                context_parts.append("\nHost Information:")
                context_parts.append(asset['host_context'][:400])
        
        # 8. ANALYST-CORRECTED PAST VERDICTS (Feedback Loop)
        try:
            from backend.storage.database import get_similar_past_verdicts
            past_verdicts = get_similar_past_verdicts(
                alert_name=alert.get('alert_name', ''),
                mitre_technique=alert.get('mitre_technique', ''),
                limit=3
            )
            if past_verdicts:
                context_parts.append("\n## 8. ANALYST-CORRECTED PAST VERDICTS:")
                context_parts.append("(Learn from previous analyst decisions on similar alerts)\n")
                for idx, pv in enumerate(past_verdicts, 1):
                    context_parts.append(f"### Past Alert {idx}: {pv.get('alert_name', 'Unknown')}")
                    context_parts.append(f"   - AI Verdict: {pv.get('ai_verdict', 'N/A')}")
                    context_parts.append(f"   - Analyst Verdict: {pv.get('analyst_verdict', 'N/A')}")
                    context_parts.append(f"   - AI was correct: {pv.get('ai_was_correct', 'N/A')}")
                    if pv.get('analyst_notes'):
                        context_parts.append(f"   - Analyst Notes: {pv.get('analyst_notes')[:200]}")
                    context_parts.append("")
        except Exception as e:
            logger.warning(f"[RAG] Could not fetch past verdicts: {e}")
        
        # 9. Current Alert Details
        context_parts.append("\n## 9. CURRENT ALERT DETAILS:")
        context_parts.append(f"Alert Name: {alert.get('alert_name', 'N/A')}")
        context_parts.append(f"MITRE Technique: {alert.get('mitre_technique', 'N/A')}")
        context_parts.append(f"Severity: {alert.get('severity', 'N/A')}")
        context_parts.append(f"Source IP: {alert.get('source_ip', 'N/A')}")
        context_parts.append(f"Dest IP: {alert.get('dest_ip', 'N/A')}")
        context_parts.append(f"Hostname: {alert.get('hostname', 'N/A')}")
        context_parts.append(f"Username: {alert.get('username', 'N/A')}")
        context_parts.append(f"Timestamp: {alert.get('timestamp', 'N/A')}")
        context_parts.append(f"Description: {alert.get('description', 'N/A')}")
        
        # 10. Correlated Logs
        if logs:
            context_parts.append("\n## 10. CORRELATED LOGS:")
            formatted_logs = self._format_logs(logs)
            context_parts.append(formatted_logs)
        
        # ======================================================================
        # SYSTEMATIC INVESTIGATION QUESTIONS (The "Analyst Checklist")
        # ======================================================================
        context_parts.append("\n" + "=" * 70)
        context_parts.append("\n## SYSTEMATIC INVESTIGATION QUESTIONS")
        context_parts.append("Answer EACH question using the evidence above:\n")
        
        # Q1: User/Account Analysis
        context_parts.append("**Q1. USER ANALYSIS:**")
        context_parts.append(f"   - User '{alert.get('username', 'Unknown')}': Is this a service account, admin, or standard user?")
        context_parts.append("   - Does this user typically perform this type of activity?")
        context_parts.append("   - Is there evidence of compromised credentials (unusual login location/time)?")
        
        # Q2: Process/Command Analysis  
        context_parts.append("\n**Q2. PROCESS CHAIN ANALYSIS:**")
        context_parts.append("   - What is the parent process? Is this parent-child relationship normal?")
        context_parts.append("   - Are command-line arguments suspicious (encoded commands, download cradles)?")
        context_parts.append("   - Is the executable signed? Located in a standard path?")
        
        # Q3: Network Analysis
        context_parts.append("\n**Q3. NETWORK ANALYSIS:**")
        context_parts.append(f"   - Source IP '{alert.get('source_ip', 'Unknown')}': Internal or external? Known bad?")
        context_parts.append(f"   - Destination IP '{alert.get('dest_ip', 'Unknown')}': Legitimate service or suspicious?")
        context_parts.append("   - Are ports/protocols expected for this type of communication?")
        
        # Q4: Temporal Analysis
        context_parts.append("\n**Q4. TIMING ANALYSIS:**")
        context_parts.append(f"   - Timestamp '{alert.get('timestamp', 'Unknown')}': Business hours or off-hours?")
        context_parts.append("   - Is this a scheduled maintenance window?")
        context_parts.append("   - Does the timing correlate with other suspicious events?")
        
        # Q5: Historical Context
        context_parts.append("\n**Q5. HISTORICAL CONTEXT:**")
        context_parts.append("   - Have we seen this exact alert before? What was the previous verdict?")
        context_parts.append("   - Is this a known false positive pattern?")
        context_parts.append("   - Are there related alerts in close time proximity?")
        
        # Q6: Business Justification
        context_parts.append("\n**Q6. BUSINESS JUSTIFICATION:**")
        context_parts.append(f"   - Host '{alert.get('hostname', 'Unknown')}': What is its role? Is it a critical asset?")
        context_parts.append("   - Is there a change ticket or maintenance task that explains this activity?")
        context_parts.append("   - Does this align with the user's job function?")
        
        # Q7: Attack Indicators
        context_parts.append("\n**Q7. ATTACK INDICATOR CHECK:**")
        context_parts.append(f"   - MITRE Technique '{alert.get('mitre_technique', 'Unknown')}': What attack stage does this represent?")
        context_parts.append("   - Are there indicators of persistence, lateral movement, or data exfiltration?")
        context_parts.append("   - Do multiple logs correlate to form an attack chain?")
        
        context_parts.append("\n" + "=" * 70)
        
        # Footer with JSON format instruction
        context_parts.append("\n## VERDICT DECISION CRITERIA:")
        context_parts.append("""
### BENIGN (False Positive) - Use when activity is NORMAL and EXPECTED:
- Administrative PowerShell/CMD usage during business hours by IT staff
- Scheduled tasks, Windows Update, system maintenance routines
- Internal vulnerability scans from known security tools (Nessus, Qualys, etc.)
- Known automation tools (Ansible, SCCM, Puppet, Chef, Jenkins)
- Software installations/updates from legitimate sources
- Backup operations, antivirus scans, disk cleanup
- Network traffic to known Microsoft, Google, AWS, internal domains
- User activity matching their normal behavioral baseline
- Events from signed/trusted executables in standard paths
WHEN BENIGN: Clearly state "This is normal administrative activity because..." or "This is a false positive - the behavior matches routine maintenance..."

### MALICIOUS - Use ONLY when there is CLEAR evidence of attack:
- Known malware signatures, hashes, or file names
- Connection to confirmed C2 servers or malicious IPs/domains
- Data exfiltration patterns (large outbound transfers to unknown destinations)
- Credential dumping tools (mimikatz, procdump on lsass, etc.)
- Lateral movement with stolen credentials
- Ransomware indicators (mass file encryption, shadow copy deletion)
- Living-off-the-land binaries used in attack chains (not just admin use)
- Persistence mechanisms (registry run keys, scheduled tasks) with malicious payloads

### SUSPICIOUS - Use when genuinely uncertain:
- Activity could be legitimate OR malicious, context is ambiguous
- Unusual but not definitively malicious behavior
- First-time behavior that deviates from baseline but has plausible explanation
- Needs human investigation to determine intent

## CONFIDENCE CALIBRATION:
- 0.90-1.00: Clear, unambiguous evidence. High certainty in verdict.
- 0.70-0.89: Strong indicators but some ambiguity. Confident but not certain.
- 0.50-0.69: Mixed signals, could go either way. Requires human review.
- Below 0.50: Insufficient data. Should NOT be used - default to suspicious if unsure.

## FALSE POSITIVE RECOGNITION - These are typically BENIGN:
- Windows/Microsoft Update processes (wuauclt, TrustedInstaller, MsMpEng)
- Legitimate admin PowerShell: Get-*, Set-*, Install-*, Update-* cmdlets
- IT ticketing/remote support tools (ServiceNow, TeamViewer, Bomgar) by IT staff
- Scheduled antivirus scans during maintenance windows
- Internal penetration testing (verify with security team schedule)
- Developer tools and IDEs (Visual Studio, VS Code, Docker, npm, pip)
- Cloud sync clients (OneDrive, Dropbox, Google Drive) in normal operation
- VPN and network authentication events
""")
        context_parts.append("\n## RESPONSE FORMAT REQUIREMENT:")
        context_parts.append("\nYou MUST respond with ONLY a JSON object. NO markdown, NO code blocks, NO explanations, NO additional text.")
        context_parts.append("Start your response directly with { and end with }.")
        context_parts.append("\nRequired JSON structure:")
        context_parts.append("""{
  "verdict": "malicious" or "benign" or "suspicious",
  "confidence": 0.0 to 1.0,
  "evidence": ["finding 1", "finding 2", "finding 3", "finding 4", "finding 5", "finding 6", "finding 7", "finding 8"],
  "investigation_answers": {
    "user_analysis": "Answer to Q1 - who is this user and is this normal for them?",
    "process_analysis": "Answer to Q2 - is the process chain legitimate?",
    "network_analysis": "Answer to Q3 - are the network connections expected?",
    "timing_analysis": "Answer to Q4 - is the timing suspicious?",
    "historical_context": "Answer to Q5 - have we seen this before?",
    "business_justification": "Answer to Q6 - is there a legitimate business reason?",
    "attack_indicators": "Answer to Q7 - what attack stage or benign pattern?"
  },
  "chain_of_thought": [
    {"step": 1, "question": "Q1-User", "finding": "What the logs show", "interpretation": "What this means for verdict"},
    {"step": 2, "question": "Q2-Process", "finding": "Process chain details", "interpretation": "Legitimate or suspicious"},
    {"step": 3, "question": "Q3-Network", "finding": "Connection analysis", "interpretation": "Expected or anomalous"},
    {"step": 4, "question": "Q4-Q5 Time/History", "finding": "Temporal and historical context", "interpretation": "Pattern recognition"},
    {"step": 5, "question": "Q6-Q7 Business/Attack", "finding": "Business justification check", "interpretation": "Final determination"}
  ],
  "reasoning": "300+ char synthesis connecting all 7 investigation answers. For BENIGN: explain the legitimate business activity. For MALICIOUS: describe the attack chain. Reference specific log IDs.",
  "recommendation": "Specific actionable steps. For BENIGN: suggest tuning rules. For MALICIOUS: containment steps. For SUSPICIOUS: what to investigate further."
}""")
        context_parts.append("\nCRITICAL REQUIREMENTS FOR YOUR ANALYSIS:")
        context_parts.append("1. LOG REFERENCES ARE MANDATORY: You MUST reference specific log entries by their ID")
        context_parts.append("   Example: 'As seen in [PROCESS-1], powershell.exe was spawned from WINWORD.EXE'")
        context_parts.append("   Example: '[NETWORK-2] shows connection to known C2 server on port 443'")
        context_parts.append("2. Every log provided above MUST be referenced in your evidence or reasoning")
        context_parts.append("3. At least 8 specific evidence points from logs, MITRE data, and historical context")
        context_parts.append("4. Chain of thought: 5 steps showing observation -> analysis -> conclusion")
        context_parts.append("5. Reasoning must be 300+ characters explaining how evidence connects")
        context_parts.append("6. Reference specific log entry IDs, MITRE tactics, and similar past incidents")
        context_parts.append("7. Explain the complete attack chain OR why this is legitimate activity")
        context_parts.append("8. DO NOT default to 'suspicious' - make a definitive call when evidence is clear")
        context_parts.append("\nYOUR EVIDENCE ARRAY MUST INCLUDE:")
        context_parts.append("- At least one reference to each log type provided (process, network, file, windows)")
        context_parts.append("- Use the exact log IDs like [PROCESS-1], [NETWORK-1], [FILE-1], [WINDOWS-1]")
        context_parts.append("- Explain what each log entry reveals about the incident")
        context_parts.append("- For BENIGN: Include evidence supporting why this is normal (e.g., 'IT admin account', 'business hours', 'signed Microsoft binary')")
        context_parts.append("\nDO NOT use markdown formatting. DO NOT wrap in code blocks. Return ONLY the raw JSON object.")
        
        # ======================================================================
        # FEW-SHOT EXAMPLES (Teach by example)
        # ======================================================================
        context_parts.append("\n" + "=" * 70)
        context_parts.append("\n## FEW-SHOT EXAMPLES")
        context_parts.append("\n### Example 1: BENIGN (IT Admin Activity)")
        context_parts.append("""Alert: "PowerShell Execution Detected"
User: admin_jsmith (IT Department)
Time: 10:30 AM (business hours)
Process: PowerShell running Get-ADUser cmdlet
Verdict: BENIGN (confidence: 0.92)
Why: IT admin running standard AD query during work hours. No encoded commands, no network callbacks, parent process is Explorer.exe (user session).""")
        
        context_parts.append("\n### Example 2: MALICIOUS (Credential Theft)")
        context_parts.append("""Alert: "LSASS Memory Access Detected"
User: svc_backup (service account)
Time: 2:47 AM (off-hours)
Process: procdump.exe dumping lsass.exe memory
Verdict: MALICIOUS (confidence: 0.95)
Why: Service account shouldn't run interactive tools. procdump on LSASS is classic credential dumping (MITRE T1003.001). Off-hours execution, no change ticket.""")
        
        context_parts.append("\n" + "=" * 70)
        
        # Join all parts
        return "\n".join(context_parts)
    
    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================
    
    def _extract_department(self, alert: Dict[str, Any]) -> str:
        """
        Extract department from hostname token or metadata.
        
        Example: "HOST-finance-laptop" -> "finance"
        """
        hostname = alert.get('hostname', '').lower()
        
        # Check for department keywords in hostname
        departments = ['finance', 'it', 'hr', 'engineering', 'sales']
        
        for dept in departments:
            if dept in hostname:
                return dept
        
        # Check if department is explicitly provided
        if 'department' in alert:
            return alert['department']
        
        return "unknown"
    
    def _extract_attack_type(self, alert_name: str) -> str:
        """
        Extract attack type from alert name.
        
        Example: "PowerShell Fileless Execution" -> "PowerShell"
        """
        if not alert_name:
            return ""
        
        alert_lower = alert_name.lower()
        
        # Common attack types
        attack_types = [
            'powershell', 'certutil', 'psexec', 'mimikatz',
            'ransomware', 'phishing', 'sql injection', 'xss',
            'dns tunneling', 'lateral movement', 'credential'
        ]
        
        for attack_type in attack_types:
            if attack_type in alert_lower:
                return attack_type
        
        # Return first word as fallback
        return alert_name.split()[0] if alert_name else ""
    
    def _format_logs(self, logs: Dict[str, List]) -> str:
        """
        Format logs dictionary into readable text with indexed entries.
        
        Args:
            logs: Dictionary with keys: network_logs, process_logs, 
                  windows_event_logs, file_activity_logs
        
        Returns:
            Formatted string with indexed log entries for AI to reference
        """
        formatted = []
        log_counts = {}
        
        # Process logs - show ALL (up to 10)
        if 'process_logs' in logs and logs['process_logs']:
            count = len(logs['process_logs'])
            log_counts['process'] = count
            formatted.append(f"\n### PROCESS LOGS ({count} entries) - YOU MUST REFERENCE THESE:")
            for idx, log in enumerate(logs['process_logs'][:10], 1):
                process_name = log.get('process_name', 'N/A')
                parent = log.get('parent_process', 'N/A')
                cmd = log.get('command_line', 'N/A')
                user = log.get('username', 'N/A')
                timestamp = log.get('timestamp', 'N/A')
                # Truncate long commands
                if len(cmd) > 300:
                    cmd = cmd[:300] + "..."
                formatted.append(f"  [PROCESS-{idx}] {process_name}")
                formatted.append(f"    Parent: {parent}")
                formatted.append(f"    Command: {cmd}")
                formatted.append(f"    User: {user}, Time: {timestamp}")
        
        # Network logs - show ALL (up to 10)
        if 'network_logs' in logs and logs['network_logs']:
            count = len(logs['network_logs'])
            log_counts['network'] = count
            formatted.append(f"\n### NETWORK LOGS ({count} entries) - YOU MUST REFERENCE THESE:")
            for idx, log in enumerate(logs['network_logs'][:10], 1):
                src_ip = log.get('source_ip', 'N/A')
                dst_ip = log.get('dest_ip', 'N/A')
                dst_port = log.get('dest_port', 'N/A')
                protocol = log.get('protocol', 'N/A')
                bytes_sent = log.get('bytes_sent', 0)
                bytes_recv = log.get('bytes_received', 0)
                timestamp = log.get('timestamp', 'N/A')
                formatted.append(f"  [NETWORK-{idx}] {src_ip} -> {dst_ip}:{dst_port} ({protocol})")
                formatted.append(f"    Bytes sent: {bytes_sent}, received: {bytes_recv}")
                formatted.append(f"    Time: {timestamp}")
        
        # Windows Event logs - show ALL (up to 10)
        if 'windows_logs' in logs and logs['windows_logs']:
            count = len(logs['windows_logs'])
            log_counts['windows'] = count
            formatted.append(f"\n### WINDOWS EVENT LOGS ({count} entries) - YOU MUST REFERENCE THESE:")
            for idx, log in enumerate(logs['windows_logs'][:10], 1):
                event_id = log.get('event_id', 'N/A')
                event_type = log.get('event_type', 'N/A')
                username = log.get('username', 'N/A')
                description = log.get('description', 'N/A')
                formatted.append(f"  [WINDOWS-{idx}] Event ID {event_id}: {event_type}")
                formatted.append(f"    User: {username}")
                formatted.append(f"    Details: {description[:200] if description else 'N/A'}")
        
        # File Activity logs - show ALL (up to 10)
        if 'file_logs' in logs and logs['file_logs']:
            count = len(logs['file_logs'])
            log_counts['file'] = count
            formatted.append(f"\n### FILE ACTIVITY LOGS ({count} entries) - YOU MUST REFERENCE THESE:")
            for idx, log in enumerate(logs['file_logs'][:10], 1):
                action = log.get('action', 'N/A')
                file_path = log.get('file_path', 'N/A')
                process = log.get('process_name', 'N/A')
                timestamp = log.get('timestamp', 'N/A')
                formatted.append(f"  [FILE-{idx}] {action}: {file_path}")
                formatted.append(f"    Process: {process}, Time: {timestamp}")
        
        # Add requirement summary
        if log_counts:
            formatted.append("\n" + "=" * 50)
            formatted.append("CRITICAL REQUIREMENT: You have been provided with:")
            for log_type, count in log_counts.items():
                formatted.append(f"  - {count} {log_type} log(s)")
            formatted.append("Your evidence MUST reference specific log entries by their ID (e.g., [PROCESS-1], [NETWORK-2]).")
            formatted.append("Failing to reference available logs will result in incomplete analysis.")
            formatted.append("=" * 50)
        
        return "\n".join(formatted) if formatted else "No logs available"


# =========================================================================
# TEST/DEMO CODE
# =========================================================================

if __name__ == "__main__":
    """Test RAG system with sample alert."""
    
    print("=" * 70)
    print("RAG SYSTEM TEST")
    print("=" * 70)
    
    # Initialize RAG
    rag = RAGSystem()
    
    # Sample alert
    test_alert = {
        "alert_name": "PowerShell Fileless Execution",
        "mitre_technique": "T1059.001",
        "severity": "critical",
        "hostname": "HOST-finance-laptop",
        "username": "USER-finance-manager",
        "source_ip": "10.20.1.45",
        "dest_ip": "185.220.101.45",
        "timestamp": "2026-01-18T14:30:00Z",
        "description": "PowerShell spawned from Word with encoded command"
    }
    
    # Sample logs
    test_logs = {
        "process_logs": [{
            "process_name": "powershell.exe",
            "parent_process": "WINWORD.EXE",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc ZAB3AG4AbABvAGEAZABTAHQA..."
        }],
        "network_logs": [{
            "source_ip": "10.20.1.45",
            "dest_ip": "185.220.101.45",
            "dest_port": 443,
            "protocol": "tcp",
            "bytes_sent": 8192
        }]
    }
    
    # Build context
    print("\nBuilding context for test alert...")
    context = rag.build_context(test_alert, test_logs)
    
    print("\n" + "=" * 70)
    print("GENERATED CONTEXT:")
    print("=" * 70)
    print(context)
    
    print("\n" + "=" * 70)
    print(f"Context length: {len(context)} characters")
    print("=" * 70)
