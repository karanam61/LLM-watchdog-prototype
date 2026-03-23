import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.storage.database import supabase

# 1. Alerts with NULL ai_verdict (would trigger rehydration)
r = supabase.table('alerts').select('id,alert_name,ai_verdict,status,created_at').is_('ai_verdict', 'null').execute()
print(f"Alerts with NULL ai_verdict: {len(r.data)}")
for a in r.data[:10]:
    print(f"  {a['created_at'][:16]} | {a['alert_name'][:50]} | status={a['status']}")

# 2. Total alerts
r2 = supabase.table('alerts').select('id', count='exact').execute()
print(f"\nTotal alerts in DB: {r2.count}")

# 3. Alerts created today
r3 = supabase.table('alerts').select('id,alert_name,created_at').gte('created_at', '2026-02-24').order('created_at', desc=True).execute()
print(f"Created today: {len(r3.data)}")
for a in r3.data:
    print(f"  {a['created_at'][:19]} | {a['alert_name'][:55]}")

# 4. Duplicate alert names (same alert ingested multiple times)
r4 = supabase.table('alerts').select('alert_name').execute()
names = [a['alert_name'] for a in r4.data]
from collections import Counter
dupes = [(name, count) for name, count in Counter(names).items() if count > 1]
print(f"\nDuplicate alerts (same name, multiple copies):")
for name, count in sorted(dupes, key=lambda x: -x[1])[:15]:
    print(f"  {count}x | {name[:60]}")
print(f"\nTotal unique names: {len(set(names))}")
print(f"Total rows: {len(names)}")
print(f"Duplicate rows: {len(names) - len(set(names))}")
