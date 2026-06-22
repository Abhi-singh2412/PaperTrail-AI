import os
import re
from pathlib import Path

# Files to process
files = list(Path("core").glob("*.py")) + [
    Path("run.py"), 
    Path("api/routes.py"), 
    Path("metadata_extractor.py")
]

# Emojis to remove
emojis = ["🔴", "🟡", "🔵", "🚨", "🆕", "⚠️", "❓", "🔮", "🔐", "🌐", "💣", "🖼️", "✅", "✔", "✘", "💾", "⏳", "❌", "✔", "⚠", "✅", "🟢"]

for path in files:
    if not path.exists():
        continue
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # 1. Remove all emojis
    for e in emojis:
        content = content.replace(e + " ", "")
        content = content.replace(" " + e, "")
        content = content.replace(e, "")
        
    # 2. Replace big separators # ──────... with # ---
    content = re.sub(r'# ─{10,}', '# ---', content)
    
    # 3. Replace smaller heading decorators # ── Section ── with # --- Section ---
    content = re.sub(r'# ── (.+?) ──+', r'# --- \1 ---', content)
    content = re.sub(r'── (.+?) ──', r'--- \1 ---', content)
    
    # 4. Remove CONCEPT blocks in docstrings (they look too tutorial-like)
    content = re.sub(r'CONCEPT \(.*?\):\n[─-]+\n.*?(?=HOW|WHAT|ATTACKS|Usage|Returns|Returns:|def )', '', content, flags=re.DOTALL)
    
    # 5. Replace ═ separators
    content = content.replace('═' * 70, '-' * 50)
    content = content.replace('═' * 60, '-' * 50)
    content = content.replace('═', '-')
    
    # 6. Make prints look more standard
    content = content.replace('PAPERTRAIL AI — METADATA FORENSICS REPORT', 'PaperTrail AI - Forensics Report')
    content = content.replace('DOCGUARD AI — METADATA FORENSICS REPORT', 'DocGuard AI - Forensics Report')
    
    # 7. Lowercase some of the over-the-top headers
    content = content.replace('FORENSIC FLAGS', 'Forensic Flags')
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

print("De-AI-ification complete.")
