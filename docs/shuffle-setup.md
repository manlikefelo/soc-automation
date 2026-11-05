# Shuffle setup: the SOAR-platform view

This repo implements the triage pipeline two ways: **code-first** (the Python package,
which is testable and transparent) and **platform** (a [Shuffle](https://shuffler.io/)
workflow that does the equivalent on an open-source SOAR). This doc covers the Shuffle
side. The workflow export is [`shuffle/alert-triage-workflow.json`](../shuffle/alert-triage-workflow.json).

Why show both: real SOC teams live in a SOAR platform, but the logic that matters.
How an alert is enriched and scored, should be readable and unit-tested. The Python
version is the source of truth for the scoring; the Shuffle version shows I can express
the same flow on the tool a team actually operates.

## The workflow, stage for stage

It mirrors the Python pipeline exactly:

```
Wazuh webhook
   -> Extract IOCs (srcip, hash, rule level)
   -> AbuseIPDB reputation   (skipped for private/lab IPs)
   -> VirusTotal hash lookup
   -> GeoIP context
   -> Risk score  (base = level/15*70, +30 top malicious signal; level>=12 escalates)
   -> Router on action:
        escalate       -> TheHive alert (sev 3) + simulated block/isolate
        analyst_review -> TheHive alert (sev 2)
        auto_close     -> log only
```

The scoring node runs the *same* formula as `src/soc_automation/scoring.py`, so the two
implementations agree on every alert.

## Install Shuffle (free, self-hosted, Docker)

```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
docker compose up -d
# UI at https://localhost:3001  (default creds set on first launch)
```

## Import the workflow

1. In the Shuffle UI: **Workflows → Import → Upload file** and pick
   `shuffle/alert-triage-workflow.json`.
2. Open the imported workflow. Some app nodes (AbuseIPDB, VirusTotal, TheHive) prompt you
   to **activate the app** and add an **authentication** entry the first time.
3. Add the API keys as Shuffle **org environment variables / auth**, matching the node
   parameters: `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`. Never paste keys into the nodes
   directly.

## Wire Wazuh to the webhook

Point Wazuh's [integrator](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
at the workflow's webhook URL so alerts POST automatically:

```xml
<!-- /var/ossec/etc/ossec.conf on the Wazuh manager -->
<integration>
  <name>custom-shuffle</name>
  <hook_url>https://<shuffle-host>:3001/api/v1/hooks/webhook_<id></hook_url>
  <level>8</level>            <!-- forward alerts at level 8+ -->
  <alert_format>json</alert_format>
</integration>
```

## Test it

Use Shuffle's **Run** button with one of this repo's sample alerts pasted as the webhook
body (e.g. [`samples/alerts/dcsync.json`](../samples/alerts/dcsync.json)). You should see
the DCSync alert route to **escalate** and create a TheHive alert, matching what
`soc-triage run samples/alerts/dcsync.json` prints locally.

## Note on the export format

Shuffle's internal workflow schema evolves between releases, so treat this JSON as a
**readable, logically-complete blueprint** of the flow rather than a guaranteed drop-in
for every Shuffle version. If a node doesn't bind on import, the app/action names above
tell you exactly what to recreate: the structure and the scoring logic are the point.
