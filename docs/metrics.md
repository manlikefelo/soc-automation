# Metrics: manual vs. automated triage

The value of this pipeline is time. Below is the enrichment + triage work an analyst
does by hand for a single alert, versus what the pipeline does automatically.

## The manual baseline (per alert)

For one alert with a source IP and a file hash, an analyst typically:

| Step | Manual action | ~time |
|------|---------------|------:|
| 1 | Read the alert, pull out the IP / hash / user | 1 min |
| 2 | Paste the IP into AbuseIPDB, read the score | 1.5 min |
| 3 | Paste the hash into VirusTotal, read the detections | 1.5 min |
| 4 | Check GeoIP / WHOIS for the source | 1.5 min |
| 5 | Decide disposition, write it up, open a ticket | 2.5 min |
| | **Total** | **~8 min** |

That's ~8 minutes of context-switching per alert, and it's the same rote lookups every
time. On a noisy day of a few hundred alerts, most of it is low-value.

## Automated

The pipeline does steps 1–5 in **one command, in well under a second** (excluding
network latency to the reputation APIs, which is cached after the first lookup):

```bash
soc-triage run alert.json --tickets tickets/
```

| | Manual | Automated |
|---|-------:|----------:|
| Time per alert | ~8 min | ~seconds |
| Consistency | varies by analyst | identical every time |
| Ticket written | manually | automatically, structured |
| Repeated IOC lookups | re-done each time | cached |

**Result: enrichment + triage that took ~8 minutes by hand runs in seconds, the same
way every time, and the analyst only sees the alerts that scored high enough to need a
human.**

## Where the time actually goes now

The analyst's remaining job is the part that *should* need a human: judging the
`analyst_review` and `escalate` tickets the pipeline surfaces, with all the enrichment
already attached. The `auto_close` bucket (low-severity, no malicious signal) never
reaches them.

## How the numbers were derived

The ~8 min manual figure is a conservative estimate of the four external lookups plus
write-up, based on doing this by hand during my IR project ([ir-threat-hunt](https://github.com/manlikefelo/ir-threat-hunt)).
The automated time is the measured pipeline runtime in offline mode; live runs add only
the API round-trips, which the cache removes on repeat IOCs.
