# Surge Workflow Optimization Reference

## Current Graph (8 nodes)

```
recon ──┬── recon_analyzer ──┬── os_analyzer ──┬── vulnerability → cvss_data_formatter → cvss_scoring ──┬── reporter → END
        └── os_finder ───────┘                 └────────────────────────────────────────────────────────┘
```

## Optimized Graph (7 nodes)

```
recon ──┬── recon_analyzer ──┬── os_analyzer ──┬── vulnerability → cvss_scoring ──┬── reporter → END
        └── os_finder ───────┘                 └──────────────────────────────────┘
```

The graph shape stays the same. The only structural change is removing `cvss_data_formatter` (replaced by deterministic Python inside `cvss_scoring`).

---

## Quality Issues Found

### 1. Dashboard keeps lowest-severity vuln per host (HIGH)

**File:** `agents/dashboard_payload.py:142-147`

The loop iterates all vulns for a given IP but overwrites `cvss`, `severity`, `cve_id` each time. Combined with the vuln agent sorting descending by CVSS, the last match is the lowest-severity vuln. Each host in the dashboard shows its least critical vulnerability instead of its worst.

**Fix:** Track the max by `predicted_score`, or accumulate all vulns per host.

### 2. `cvss_data_formatter` LLM can corrupt vuln data (HIGH)

**File:** `agents/data_formatting_agent.py`

This agent uses an entire LLM call to reshape JSON from one schema to another. An LLM can silently drop entries, change CVSS values, invent or mangle CWE codes, and produce inconsistent date formats. Every vulnerability that reaches the ML scorer passes through this fragile point.

**Fix:** Remove the `cvss_data_formatter` node entirely. Replace with a deterministic Python mapping function inside `cvss_scoring.py`. The schema transformation is fully deterministic and does not need LLM reasoning.

### 3. Recon XML aggregation only reads the first scan directory (MEDIUM)

**File:** `agents/recon_agent.py:263`

`all_xml_output_to_txt(xml_dirs[0])` only processes the first successful scan's folder. If the recon agent ran multiple iterations with escalated scans, the deeper/richer XML from later iterations is lost. The analysis agent and reporter only see the initial shallow scan data.

**Fix:** Iterate all `xml_dirs` and concatenate across them.

### 4. `recon_analysis` reads XML from the wrong key (MEDIUM)

**File:** `agents/recon_analysis.py:55`

It reads `recon_results.get("all_xml_content", "")`, but `all_xml_content` is a top-level state key, not nested inside `recon_results`. The recon agent writes it to `state["all_xml_content"]` (line 265 of `recon_agent.py`). So the analysis LLM gets an empty string for XML data and produces a lower-quality analysis.

**Fix:** Read `state["all_xml_content"]` instead of `recon_results.get("all_xml_content", "")`.

### 5. OS fingerprint XML only keeps the last batch (LOW-MEDIUM)

**File:** `agents/os_fingerprint_agent.py:102-104`

`os_xml_content` is overwritten each batch iteration, so only the last batch's raw XML survives. If you have 30 hosts split into 3 batches, only hosts 21-30's XML is preserved.

**Fix:** Append instead of overwrite (`os_xml_content += f.read()`).

### 6. `recon_agent` returns full state instead of partial update (LOW)

**File:** `agents/recon_agent.py:268`

`return state` returns the entire state dict. Every other agent correctly returns only the keys they changed (e.g., `return {"os_analysis": ...}`). With LangGraph, returning the full state can cause stale values to overwrite updates from parallel branches during fan-in merges. Since `recon` runs first (before any fan-out), this doesn't cause a conflict today, but it's a latent bug.

**Fix:** Return only the keys recon modifies: `return {"recon_results": ..., "all_xml_content": ...}`.

---

## What's Already Working Well

- **Fan-out after recon** — `recon_analyzer` and `os_finder` run in parallel, correctly since they are independent consumers of recon data.
- **Fan-in at `os_analyzer`** — waits for both branches before proceeding. No state key conflicts (`recon_analysis` vs `os_fingerprint_results`/`os_xml_content`).
- **Fan-in at `reporter`** — waits for `os_analyzer` and `cvss_scoring`. No state key conflicts (`os_analysis` vs `vuln_scoring`/`topology`).
- **Convergence logic in recon** — delta detection (new hosts/ports/services) with hard iteration + time budget caps prevents infinite loops.
- **Intermediate dashboard snapshots** — `recon_analysis`, `vulnerability`, and `cvss_scoring` all write `dashboard_data.json` so the frontend gets progressive updates.
- **`os_analyzer` stays on the critical path before `vulnerability`** — its OS summary helps the vuln agent make better CVE relevance decisions. This dependency is correct for quality.

---

## Changes Summary

| Change | File(s) | Type |
|--------|---------|------|
| Remove `cvss_data_formatter` node, replace with Python function | `workflow/graph.py`, `agents/cvss_scoring.py`, delete `agents/data_formatting_agent.py` | Structural |
| Fix dashboard vuln loop to keep highest-severity per host | `agents/dashboard_payload.py` | Bug fix |
| Fix `recon_analysis` to read `state["all_xml_content"]` | `agents/recon_analysis.py` | Bug fix |
| Aggregate all XML dirs in recon, not just first | `agents/recon_agent.py` | Bug fix |
| Append OS XML across batches instead of overwrite | `agents/os_fingerprint_agent.py` | Bug fix |
| Return partial state from `recon` agent | `agents/recon_agent.py` | Bug fix |
