# Optional SIEM import examples — the lab is fully solvable without these.

## Manual / plain parsing (works offline, no SIEM needed)

```python
import json
for line in open('artifacts/logs/incident-events.jsonl'):
    rec = json.loads(line)
    print(rec['timestamp_utc'], rec['source_event_id'], rec['category'])
```

## Splunk SPL (onboard each file as its own sourcetype)

Extract the row arrays into events:

```spl
index=eaitm_lab sourcetype=aitm:signins
| spath path=records{} output=recs
| mvexpand recs
| spath input=recs
| eval ts=coalesce(timestamp_utc, created_utc)
| sort 0 ts
```

Correlate by account and event ID across all datasets:

```spl
index=eaitm_lab
| eval event_id=coalesce(event_id, source_event_id, alert_id)
| stats values(source_dataset) AS sources, values(actor) AS actors,
        values(derived_summary) AS summary by event_id
```

Show everything involving the suspicious external IP (`203.0.113.87`):

```spl
index=eaitm_lab
| search "203.0.113.87"
| eval ts=coalesce(timestamp_utc, created_utc)
| sort 0 ts
```

## Elasticsearch / OpenSearch

Ingest each JSON file into an index (`eaitm-*`), then:

```json
GET eaitm-*/_search
{
  "query": { "match_phrase": { "source_ip": "203.0.113.87" } },
  "sort": [{ "timestamp_utc": "asc" }]
}
```

JSONL (one object per line) can be loaded with:

```python
import json
with open('artifacts/logs/incident-events.jsonl', encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        # POST: PUT /eaitm-normalized/_doc/<id>
        print(rec['source_event_id'], json.dumps(rec))
```

## CSV workflow

`artifacts/logs/incident-timeline.csv` is a pre-sorted index of the
normalized stream: open it in any spreadsheet tool, filter by
`user_account`/`actor` or `category`, and pivot on the `event_id`.
