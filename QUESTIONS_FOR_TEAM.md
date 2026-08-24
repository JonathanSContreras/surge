# Questions & Missing Information for the Surge Final Report

These items are flagged with `[TODO]` markers in the .docx and need team input before the report is finalized.

---

## Cover Page

1. **Project Advisor name(s):** Who is/are the faculty advisor(s) for the capstone project? Dr. Stephen Lyford for 90% of the project. We also reached out to Mr. Aguilar for Full-Stack website questions like the architecure, website details (layouts and information).
2. **Sean and Tauren's last names:** Sean Moning and Taurean Muhammad
3. **Submission date:** April 10th

---

## Section 1: Formal Project Description

4. **Block diagram / system architecture figure:** The report needs a visual block diagram showing the full system (Lab Network → Agent Pipeline → Backend → Dashboard). Do you have one, or should I generate a description for you to diagram? This is explicitly required by the report guidelines. The Figures are already in the document

---

## Section 2: Engineering Design Specification

5. No major gaps — drafted from codebase audit. Review for accuracy.

---

## Section 5: Constraints / Section 7: Cost Analysis

6. **Cost figures:** What are the approximate costs for:
   - OpenRouter API spend to date? In mid-Janurary of 2026, we started with $50 and as of April 9th, we have $46.5723 left over meaning we have spend $3.4277
   - Were any hardware purchases made out of pocket? No hardware purchases were made.
   - Is the Vercel deployment on the free tier? Yes on free tier
   - Any domain name costs? Nope, ussing vercels free tier
   - Were the Cisco networking devices (switches, routers, firewall) provided by the department or purchased? Provided by the department
   - Approximate total project budget? $50 included API credits, $0 without.

---

## Section 6: Material Learned Outside the Classroom

7. **Per-team-member additions:** Each team member should review this section and add any technologies or topics they self-taught that aren't already listed. Specific prompts:
   - **Brianna:** What ML/AI topics did you learn beyond coursework? (e.g., XGBoost training specifics, sentence-BERT, feature engineering for CVE data). langgraph and prompt engineering are two big ones
   - **Sean:** What network security tools/techniques did you learn independently? (e.g., specific nmap scan modes, CVE database navigation, CIRCL API)
   - **Tauren:** What Cisco configuration topics required self-study? (e.g., ASA firewall rules, NAT troubleshooting, VLAN trunking details)
   - **Jonathan:** Anything beyond what's listed re: LangGraph, GPU optimization, FastAPI async patterns, Docker Compose? All full-stack website stuff was known prior, though I had to learn more D3. I did have to learn how to set up our ubuntu server to host both models.

---

## Section 7: Cost Analysis

8. See question 6 above — need actual dollar amounts for the cost table.

---

## Table of Figures

9. **Figures to insert:** The report currently has no embedded figures. The following are recommended (and some are required):
   - **Figure 1:** System architecture block diagram (required by report guidelines)
   - **Figure 2:** LangGraph agent pipeline DAG (workflow/graph.py topology)
   - **Figure 3:** Network topology diagram (from the Senior Project Network Design PDF)
   - **Figure 4:** Dashboard screenshot (main view with topology graph)
   - **Figure 5:** Scans page screenshot
   - **Figure 6:** Exploits page screenshot
   - **Figure 7:** Reports page screenshot
   - **Figure 8:** Database ER diagram
   - **Figure 9:** Governance tier diagram (low/medium/high scan tiers)

   Please provide screenshots or diagrams, or confirm I should generate descriptive placeholders.

   Already provided

---

## References

10. **Additional references:** Add any textbooks, research papers, video tutorials, or documentation sources used during the project that should be formally cited. The current list covers the major frameworks/databases but may be missing course-specific or research-specific citations.
- the langgraph documentation
- The CIRL API

---

## General Review

11. **Accuracy check on LLM model names:** The codebase references `gpt_oss:20b` and `z-ai/glm-5` via OpenRouter. Are these the current/final models in use, or have they changed? Your context mentioned Qwen3-32B on GPU 0 — the code shows it's configurable. Confirm which models are in production.
12. **Docker Compose:** Your context mentioned Docker Compose for deployment, but no Dockerfile or docker-compose.yml was found in the codebase. Has this been set up elsewhere, or is it still planned? We will do it later.
13. **Agent mode (autonomous vs. manual):** The API supports both. Is "manual" mode implemented, or is it a stub? Should the report describe it? Manual mode will be removed from the web site.
14. **Scan profiles:** The database has a ScanProfileModel for saved scan configurations. Is this feature active in the frontend?

---

## Formatting Reminders

- The report description requires **minimum 30 pages, double-spaced**.
- The current draft is approximately 20-25 pages. Adding figures, expanding the cost analysis, and fleshing out team-specific material learned sections should bring it to the required length.
- Each major section should begin on a new page (already handled in the .docx).
- Font: Times New Roman 12pt (already set).
- Remember to update the Table of Contents after inserting figures (right-click TOC → Update Field in Word).
