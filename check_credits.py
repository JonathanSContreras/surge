"""
Usage: python check_credits.py
Queries the OpenRouter API to show current credit usage against the $50 budget.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    print("ERROR: OPENROUTER_API_KEY not found in .env")
    exit(1)

resp = requests.get(
    "https://openrouter.ai/api/v1/auth/key",
    headers={"Authorization": f"Bearer {api_key}"},
    timeout=10,
)
resp.raise_for_status()

data = resp.json().get("data", {})
usage     = data.get("usage", 0)       # dollars spent
limit     = data.get("limit") or 50.0  # dollars allocated
remaining = limit - usage
pct_used  = (usage / limit * 100) if limit else 0

bar_filled = int(pct_used / 5)
bar = "█" * bar_filled + "░" * (20 - bar_filled)

print(f"\n  OpenRouter Credit Usage")
print(f"  ─────────────────────────────────")
print(f"  [{bar}] {pct_used:.1f}%")
print(f"  Spent:     ${usage:.4f}")
print(f"  Remaining: ${remaining:.4f}")
print(f"  Limit:     ${limit:.2f}")
print()
