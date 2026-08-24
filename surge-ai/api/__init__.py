"""
Surge API package.

Loads .env at package import time. This must happen here rather than in
main.py: `api.db` and `api.activity` read DATABASE_URL with os.getenv at
*module* scope, and Python executes this __init__ before either of them.
Putting load_dotenv() in main.py would run too late — DATABASE_URL would
still be unset and the app would silently fall back to SQLite.

(Under Docker Compose this never showed up, because env came from the
compose `environment:` block rather than a .env file.)
"""

from dotenv import load_dotenv

load_dotenv()
