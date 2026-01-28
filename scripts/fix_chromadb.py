"""
Quick fix script to re-seed ChromaDB collections
Run this if you see: "Error creating hnsw segment reader: Nothing found on disk"
"""

import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Now import and run the seeding
from backend.scripts.seeding.seed_rag import seed_rag_db

if __name__ == "__main__":
    print("\n" + "="*60)
    print("CHROMADB FIX - Re-seeding all RAG collections")
    print("="*60 + "\n")
    
    try:
        seed_rag_db()
        print("\n" + "="*60)
        print("[OK] ChromaDB collections re-seeded successfully!")
        print("Restart the server for changes to take effect.")
        print("="*60 + "\n")
    except Exception as e:
        print(f"\n[ERROR] Failed to seed: {e}")
        import traceback
        traceback.print_exc()
