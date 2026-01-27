# Quick Start Guide - AI-SOC Watchdog Dashboards

## System is Running! 🎉

Your complete AI-SOC Watchdog system with all 5 dashboards is now LIVE!

---

## 🌐 Access Your Dashboards

Open your browser and navigate to any of these URLs:

### 1️⃣ Analyst Console
**URL**: http://localhost:5173/analyst

**What it does**:
- Main security operations dashboard
- View all alerts with AI analysis
- Click any alert to expand details
- See network, process, and file logs
- Create investigation cases
- Close resolved alerts

**Key Features**:
- Real-time alert feed
- AI verdict badges (Malicious/Suspicious/Benign)
- Evidence chain visualization
- Correlated log tabs

---

### 2️⃣ System Metrics
**URL**: http://localhost:5173/performance

**What it does**:
- Monitor system health in real-time
- Track AI costs and token usage
- View processing statistics
- See error logs

**Key Features**:
- CPU & Memory usage (REAL, not fake!)
- AI cost tracking ($ per alert)
- 24-hour trend charts
- Alert processing volume
- Verdict distribution pie chart
- Recent error viewer

**Updates**: Every 5 seconds automatically

---

### 3️⃣ System Debug
**URL**: http://localhost:5173/debug

**What it does**:
- Live trace of EVERY system operation
- See every API call, function, worker action
- Human-readable explanations
- Filter and search operations

**Key Features**:
- Terminal-style live viewer
- Category filters (API, FUNCTION, WORKER, AI, etc.)
- Search box for finding specific operations
- Pause/Resume streaming
- Auto-scroll toggle
- Expandable details for each operation

**Updates**: Every 1 second (real-time feel)

**Perfect for**:
- Understanding what the system is doing
- Debugging issues
- Learning how alerts flow through the system
- Non-coders can understand everything!

---

### 4️⃣ RAG Visualization
**URL**: http://localhost:5173/rag

**What it does**:
- Show how AI uses the knowledge base
- See what documents are retrieved
- Track RAG query performance
- Prove AI uses real knowledge

**Key Features**:
- RAG statistics dashboard
- Knowledge base status (7 collections)
- Query distribution by source
- Alert-specific inspection
- Expandable retrieved documents
- Evidence of AI utilizing knowledge

**How to use**:
1. Look at the overview statistics
2. Select an alert from the list
3. See exactly what RAG data was retrieved
4. Expand each source to view documents
5. Confirm AI used that knowledge in analysis

---

### 5️⃣ AI Transparency
**URL**: http://localhost:5173/transparency

**What it does**:
- PROVE AI is NOT hallucinating
- Verify analysis legitimacy
- Show evidence chain
- Cross-reference AI claims with data

**Key Features**:
- Verification score (0-100%)
- Final verdict (VERIFIED/WARNING/CONCERN)
- Facts found vs. missing evidence
- RAG knowledge usage proof
- Original alert data comparison
- AI reasoning breakdown
- Chain of thought visualization
- Deep vs. shallow analysis stats

**How to use**:
1. Check the summary statistics
2. Select an alert to verify
3. See the verification score
4. Expand sections to see details:
   - Verification Analysis (what was found/missing)
   - Original Alert Data
   - AI Analysis Output
   - Correlated Logs

**This dashboard answers**:
- "Is the AI making things up?"
- "Did the AI use the RAG knowledge?"
- "Where did the AI get its evidence from?"
- "Can I trust this verdict?"

---

## 🎯 Quick Workflow

### For Security Analysts:
1. Start at **Analyst Console** to see new alerts
2. Click alert to investigate with logs
3. Switch to **AI Transparency** to verify the analysis
4. Check **RAG Visualization** to see what knowledge was used
5. Return to **Analyst Console** to create case or close alert

### For System Administrators:
1. Check **System Metrics** for health status
2. Look at **System Debug** for operational trace
3. Review error counts in metrics
4. Use Debug search to investigate issues

### For Data Analysts:
1. Use **System Metrics** for performance trends
2. Analyze AI cost patterns
3. Check **RAG Visualization** for knowledge usage
4. Review **AI Transparency** for analysis quality

### For Demonstrating to Stakeholders:
1. Show **Analyst Console** - main functionality
2. Show **AI Transparency** - prove legitimacy
3. Show **System Debug** - complete observability
4. Show **System Metrics** - performance and costs

---

## 🔍 What to Look For

### In Performance Dashboard:
- ✅ CPU should be under 80%
- ✅ Memory usage stable
- ✅ AI costs accumulating (shows it's working)
- ✅ Alerts being processed
- ✅ No red errors in error log

### In Debug Dashboard:
- ✅ Steady stream of operations (shows system is active)
- ✅ Green "success" status (most operations)
- ✅ "POST /ingest" entries (alerts being ingested)
- ✅ "AI Analysis" entries (AI working)
- ✅ Human explanations for each operation

### In RAG Dashboard:
- ✅ Query count increasing
- ✅ All 7 collections showing "active"
- ✅ Documents being retrieved
- ✅ AI using multiple sources

### In Transparency Dashboard:
- ✅ Verification scores 70%+ (good)
- ✅ "VERIFIED" verdicts
- ✅ Facts found > 0
- ✅ RAG usage showing multiple sources
- ✅ Deep analysis count > Shallow analysis

---

## 🚨 Troubleshooting

### Dashboard Shows "Loading..." Forever
- Check **System Debug** dashboard
- Look for errors in recent operations
- Check **Performance > Recent Errors**

### No Alerts Showing
- Alerts need to be ingested via API
- Run data generator: `py generate_realistic_data.py`
- Check **Debug Dashboard** for "POST /ingest" entries

### Metrics Look Wrong
- All metrics are REAL
- If CPU/Memory seem low, that's good!
- AI costs increase as alerts are analyzed
- Check **Debug Dashboard** to confirm system activity

### RAG Not Showing Data
- Ensure alerts have been analyzed by AI
- Select an alert that has AI verdict
- Check **Performance** for "RAG Queries" count

### Transparency Shows Low Score
- This is HONEST scoring
- Low score means AI couldn't verify claims
- Could indicate:
  - Not enough correlated logs
  - AI made assumptions
  - Need more RAG data

---

## 💡 Pro Tips

1. **Keep System Debug open** while testing - you'll see everything happening
2. **Use Chrome DevTools Network tab** to see API calls
3. **Pause Debug stream** when you want to read specific operations
4. **Use Search in Debug** to find specific alert IDs or operations
5. **Export Transparency proof** by copying the JSON for reports
6. **Compare multiple alerts** to see AI gives unique analysis

---

## 📊 Understanding the UI

### Color Coding:
- **Cyan/Blue**: Normal operations, info
- **Green**: Success, benign verdicts
- **Yellow**: Warnings, suspicious verdicts
- **Red**: Errors, malicious verdicts
- **Purple**: AI-specific operations

### Icons:
- 🔄 Spinning: Loading/Processing
- ✓ Checkmark: Success/Verified
- ⚠️ Warning: Caution
- ❌ X: Error/Failed
- 🔍 Magnify: Search/Inspect
- 🧠 Brain: AI operations

### Progress Bars:
- Shows utilization (CPU, Memory)
- Width = percentage
- Color = severity

---

## 🎓 Learning the System

### Start Here:
1. Open **Analyst Console** - get familiar with alert cards
2. Click an alert - see the tabs and logs
3. Open **System Debug** - watch operations stream
4. Ingest a new alert - watch it flow through Debug
5. Check **Transparency** - verify the analysis

### Advanced:
1. Compare multiple alerts in Transparency
2. Track specific RAG sources being used
3. Monitor AI costs over time
4. Search Debug for specific function calls
5. Analyze trends in Performance charts

---

## 🏁 You're All Set!

The system is **fully operational** and all dashboards are **working perfectly**.

**Next Steps**:
1. Browse each dashboard
2. Ingest some test alerts if needed
3. Watch the Debug dashboard to see live operations
4. Verify AI analysis in Transparency
5. Show it off! 🎉

**Questions or Issues?**
- Check **System Debug** first (tells you everything)
- Look at **Performance > Errors**
- All operations are logged with explanations

---

**Enjoy your state-of-the-art AI-SOC system!** 🛡️🚀
