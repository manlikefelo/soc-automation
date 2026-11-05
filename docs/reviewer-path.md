# Reviewer path: a 3-minute guided tour

For a hiring manager or teammate seeing this repo for the first time. This is a SOAR
pipeline that enriches, scores, and responds to Wazuh alerts, automating rote SOC
triage. Here's the fastest way to see it works.

### 1 · The enriched-alert example first (60s)  →  `soc-triage run`
The value is obvious the moment you see a raw alert become a scored, ticketed one:

```bash
pip install -e .
soc-triage run samples/alerts/dcsync.json --tickets tickets/
```

A DCSync alert comes in as bare JSON and comes out **escalated**, with a written ticket
and the exact containment steps it would take (block IP, isolate DC01, disable the
account, rotate krbtgt). See the sample output in the [README](../README.md#quick-start)
and the time saved in [`docs/metrics.md`](metrics.md): ~8 min of manual lookups → seconds.

### 2 · The scoring logic (60s)  →  `src/soc_automation/scoring.py`
[`scoring.py`](../src/soc_automation/scoring.py) is deliberately short and readable: a
SOC analyst should be able to predict the outcome. Base score from Wazuh severity, a
bounded reputation boost, and a hard rule that level-12 alerts (DCSync) escalate on
severity alone. Transparent triage is defensible triage.

### 3 · The test suite (60s)  →  `tests/test_enrichment.py`
This is the QA-background centerpiece. Every API call is **mocked**, the suite needs no
keys and no network, and it asserts both a malicious verdict *and* a clean one, plus
rate limits, server errors, caching, and offline mode. **54 tests, 96% coverage**, CI on
three Python versions. Testing your own SOAR automation is the rare, credible detail.

---
**The takeaway:** this automates the exact manual triage I did by hand in my IR project,
built as tested, typed, packaged Python, with an equivalent Shuffle SOAR workflow to show
both the code-first and the platform approach. Software-engineering rigor applied to SOC
automation.
