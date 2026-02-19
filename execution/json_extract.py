from typing import Any
import datetime
import json
import re

def extract_json(raw_text: str, iteration: int | None = None) -> Any:
    """
    Extracts the FIRST valid JSON object or array from raw LLM output.
    Supports both `{}` and `[]`.
    """

    if not raw_text or not raw_text.strip():
        print(f"[{datetime.datetime.now()}] ~ EMPTY MODEL OUTPUT")
        return None

    # Try array first (vuln agents, formatters)
    array_match = re.search(r"\[[\s\S]*\]", raw_text)
    if array_match:
        try:
            parsed = json.loads(array_match.group(0))
            print("parsed", parsed)
            print(f"[{datetime.datetime.now()}] ~ Extracted valid JSON ARRAY")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[{datetime.datetime.now()}] ~ Invalid JSON ARRAY: {e}")

    # Fallback: try object (recon agent)
    obj_match = re.search(r"\{[\s\S]*\}", raw_text)
    if obj_match:
        try:
            parsed = json.loads(obj_match.group(0))
            print(f"[{datetime.datetime.now()}] ~ Extracted valid JSON OBJECT")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[{datetime.datetime.now()}] ~ Invalid JSON OBJECT: {e}")

    print(f"[{datetime.datetime.now()}] ~ NO VALID JSON FOUND")
    return None