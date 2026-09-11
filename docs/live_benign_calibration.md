# Live benign-traffic calibration

## Purpose

The generic model was trained on malware/botnet flow data. Ordinary HTTPS
traffic can therefore receive a high probability even when there is no attack.
This live-only calibration workflow measures that behavior before changing any
threshold or model artifact.

Calibration is valid only when the capture contains known-benign activity.
The output is a false-positive measurement, not a threat-detection accuracy
claim.

## Workflow

1. Start the dashboard live capture with no target filter, or with the IP
   addresses of a trusted site.
2. Browse only known-benign sites for one to three minutes.
3. Stop the capture.
4. Request:

   ```text
   GET http://127.0.0.1:8000/api/live/calibration
   ```

5. Record the probability quantiles and the false-positive rate at each
   candidate threshold.

The endpoint summarizes the scored flows currently retained by the live
session. The session keeps a bounded flow set, so the result describes the
retained sample rather than every packet ever observed.

## Output

- `p50`, `p90`, `p95`, `p99`, and `max` probability quantiles
- Number of flows at each candidate threshold
- Estimated false-positive rate at `0.50`, `0.75`, `0.90`, `0.95`, and `0.99`
- Capture metadata showing whether a website filter was active

Do not choose a new production threshold from one website or one short
capture. Collect multiple normal sessions and report the sample size and
sites used. A threshold that reduces benign false positives can also reduce
recall for real attacks, so attack validation must be repeated separately.

## Architecture boundary

This workflow does not retrain the model, alter model files, change offline
PCAP/Parquet parsing, or change replay behavior. It is restricted to the live
dashboard path and is read-only.
