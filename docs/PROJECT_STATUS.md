# SIH-145 Project Status and Upgrade Roadmap

**Last updated:** 2026-09-11  
**Project:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Repository:** SIH-145

## 1. Project objective

The project implements a passive, metadata-only cyber-threat detection
pipeline for traffic observed through a one-way monitoring path. The system
must:

- ingest PCAP, Parquet, or a live mirrored interface;
- process traffic incrementally instead of only at the end of a capture;
- extract flow, timing, direction, rate, protocol, and DNS metadata;
- detect and score suspicious behavior;
- produce standardized alerts with evidence;
- display replayed and live results in a dashboard;
- never send probes, complete handshakes, decrypt payloads, block traffic, or
  issue commands back into the monitored network.

The intended operational model is:

```text
Passive mirror / data diode
        -> ingest
        -> flow reconstruction
        -> metadata features
        -> anomaly + ML + specialist evidence
        -> standardized alerts
        -> dashboard / SOC decision
```

The system detects and reports. A separate authorized SOC, SIEM, SOAR, or
firewall may decide whether to respond.

## 2. Work completed from the beginning

### 2.1 Repository and data foundation

1. Inspected the supplied project, datasets, existing scripts, reports, and
   dashboard structure.
2. Established the offline PCAP/Parquet processing path.
3. Cleaned the main flow dataset:
   - approximately 455,641 flow rows;
   - 39 columns;
   - remaining NaN and infinite values handled;
   - feature preparation documented.
4. Preserved a strict boundary between offline analysis and live acquisition so
   live-only changes do not silently alter existing replay behavior.

### 2.2 Machine-learning and anomaly pipeline

5. Implemented the initial multi-class classifier and audited its weak
   performance.
6. Built improved binary benign-versus-malicious variants.
7. Hardened the main XGBoost classifier and evaluated it with cross-validation.
8. Recorded the strongest main-model result:
   - accuracy approximately **0.983**;
   - weighted F1 approximately **0.990**;
   - ROC-AUC approximately **0.999**;
   - precision approximately **0.999**;
   - recall approximately **0.981**.
9. Verified that removing the `TCP` feature did not materially reduce the
   result, reducing concern that the model depends on one obvious feature.
10. Implemented the custom Kalman anomaly engine for streaming numeric
    measurements such as rate, inter-arrival time, and SYN counts.
11. Fixed non-finite measurement handling so invalid values cannot poison
    Kalman state, covariance, or noise.
12. Added Stage 5 score fusion:

```text
bounded_kalman_anomaly = 1 - exp(-anomaly_score / 3)
confidence = 0.7 * classifier_probability
           + 0.3 * bounded_kalman_anomaly
```

### 2.3 Dataset-specific models

13. Added the supplied domain/DGA-style classifier:
   - accuracy approximately **0.9293**;
   - macro F1 approximately **0.7886**;
   - weighted F1 approximately **0.9298**;
   - minority-class F1 approximately **0.5102**.
14. Added a capture-level Mythic HTTP C2 classifier:
   - accuracy approximately **0.7236**;
   - precision approximately **0.3985**;
   - recall approximately **0.7821**;
   - F1 approximately **0.5279**;
   - ROC-AUC approximately **0.8470**.
15. Documented that these results are dataset-specific and must not be
    presented as universal accuracy for all network traffic.

### 2.4 Offline replay and standardized alerts

16. Implemented deterministic row-by-row replay for cleaned Parquet data.
17. Added alert output in JSON Lines format.
18. Added the Pydantic `ThreatAlert` contract with:
   - UTC timestamp;
   - flow identifier;
   - threat class;
   - confidence;
   - severity;
   - anomaly score and level;
   - supporting evidence;
   - model name.
19. Added conversion helpers so offline/dashboard/live alerts use the same
    contract.
20. Documented the current limitation that the original dataset lacks complete
    timestamps and stable network identity fields, so offline replay uses
    deterministic row order and row index identifiers where necessary.

### 2.5 Dashboard and live capture

21. Built a FastAPI backend and static web dashboard for PCAP upload,
    model selection, threshold selection, packet limits, flow tables, scores,
    evidence, and alerts.
22. Added Windows Npcap/Scapy live capture with interface discovery.
23. Validated the working Wi-Fi adapter and Npcap interface on the development
    machine.
24. Added bounded live state:
   - idle flow expiration after 60 seconds;
   - maximum 5,000 active flows;
   - packet, analyzed-packet, and ignored-packet counters.
25. Added optional live-only IPv4/IPv6 target filtering.
26. Added live IPv6 TCP, UDP, and ICMPv6 recognition while preserving the
    existing offline IPv4-focused parser.
27. Added benign-capture calibration with probability quantiles and estimated
    false-positive rates. Two observed benign samples were approximately:
   - 3.6% flagged at threshold 0.50;
   - 3.0% at 0.75;
   - 2.3% at 0.90;
   - 1.7% at 0.95;
   - 0.3% at 0.99.

These calibration values are not attack recall or overall detection accuracy.

### 2.6 Live specialist evidence

The live path now contains independent, metadata-only evidence rules for all
six SIH threat categories:

| SIH category | Current live evidence |
|---|---|
| Volumetric/protocol DDoS | SYN-flood and UDP-flood rate/flag evidence |
| Botnet C2 beaconing | Repeated-flow periodicity and inter-arrival jitter |
| DGA/DNS tunnelling | DNS label length, entropy, digit ratio, and total-name length |
| Malware in TLS/QUIC | High-rate TLS/QUIC transport metadata anomaly |
| Reconnaissance/port scanning | Rolling source-to-port/host fan-out |
| Data exfiltration | Directional outbound-volume and byte-ratio anomaly |

Synthetic validation was completed for positive and negative cases covering:

- port scanning;
- SYN flooding;
- UDP flooding;
- suspicious DGA-like DNS;
- ordinary DNS negative cases;
- periodic and irregular beacon timing;
- high-rate TLS-like and QUIC-like flows;
- normal low-volume HTTPS;
- outbound-heavy and inbound-heavy transfers.

These specialist rules are evidence heuristics. They are not yet labeled
accuracy measurements and do not prove that a real attack occurred.

### 2.7 Real-time alert delivery and UI

28. Added `/ws/live-alerts` for real-time alert and status delivery.
29. Retained HTTP polling as a fallback.
30. Sends each alert once per flow per WebSocket connection and sends status
    snapshots approximately every 250 ms.
31. Added a visible browser alert feed retaining up to 100 recent alerts.
32. Added severity, threat-class, confidence, timestamp, flow ID, and reason
    display.
33. Added a browser-only clear-feed control.
34. Reloaded the dashboard and confirmed:
    - `connectLiveAlerts` is available;
    - `renderAlerts` is available;
    - the alert feed exists;
    - the clear button exists;
    - the dashboard still exposes the live controls and six-category coverage.

## 3. Current architecture

### Offline path

```text
PCAP/Parquet
  -> flow records
  -> feature extraction and cleaning
  -> Kalman anomaly scoring
  -> XGBoost inference
  -> Stage 5 confidence/severity/evidence
  -> JSON/report/dashboard output
```

### Live path

```text
Npcap interface
  -> Scapy passive packet callback
  -> bounded in-memory bidirectional flows
  -> live metadata and specialist evidence
  -> generic model + anomaly scoring
  -> ThreatAlert
  -> FastAPI status + WebSocket + dashboard
```

The live path uses canonical bidirectional flow identity while preserving the
first observed direction for directional analysis. Full payload contents are
not used.

## 4. Current strengths

- The prototype is passive and alert-only.
- No public-site scanning, probing, blocking, or traffic modification is used.
- No TLS/QUIC payload decryption is performed.
- The dashboard supports both replayed and live observations.
- All six SIH threat categories have a live evidence path.
- Alerts have a shared, validated schema.
- Live state is bounded to avoid unbounded memory growth.
- WebSocket streaming is implemented and browser-verified.
- Every major build has a dedicated Markdown document and a build-log entry.

## 5. Current limitations and evidence gaps

1. The main classifier's strong score is an offline dataset result, not a
   guarantee of real-world performance.
2. Generic malicious probability can produce false positives on ordinary
   encrypted web traffic because of dataset shift.
3. Live specialist rules have synthetic validation but no complete labeled
   precision/recall/F1 evaluation.
4. The live TLS/QUIC detector uses port, packet, byte, and rate metadata only.
   JA3/JA4 fingerprints are not currently implemented.
5. DGA and DNS tunnelling detection is heuristic and does not yet use a
   fully trained n-gram model in the live path.
6. The live beacon rule can also match legitimate keepalives, updates, or
   monitoring traffic.
7. Large outbound transfers can be legitimate backups, uploads, or
   synchronization.
8. Offline flow identity and timestamp coverage are limited by the supplied
   dataset.
9. A first offline throughput and bounded-latency benchmark is now recorded.
   A separate live Npcap benchmark is still needed before making live
   interface performance claims.
10. Reconnecting WebSocket clients can still benefit from server-side alert
    history or a cursor.
11. Frontend alert rendering should be explicitly escaped before treating the
    dashboard as production-hardened.

## 6. Remaining upgrades

### Priority 1 — Required for a strong SIH demonstration

#### Upgrade 1: throughput and latency benchmark — offline phase complete

Measure and document:

- flows per second;
- packets per second;
- approximate Mbps;
- median and P95 processing latency;
- alert emission latency;
- memory usage during a sustained run;
- behavior at the configured 5,000-flow bound.

This is the most important remaining requirement because the problem statement
explicitly requires a defined and demonstrated throughput target.

The first 10,000-row offline run measured 1,750.26 flows/sec, estimated
3.58 Mbps, P50 latency of 0.4446 ms, and P95 latency of 0.8721 ms. These are
replay/inference measurements after Parquet loading. The live Npcap path still
needs a separate authorized benchmark.

The live callback benchmark is now implemented in
`src/benchmark_live.py`. Its default in-memory mode measures the exact
`LiveSession.on_packet` path without touching the network. The optional Npcap
mode is bounded and passive; it must be run only on an authorized interface.
The first safe 1,000-packet run measured 437.97 callback packets/sec and
1,000 active flows. Its flagged-flow count is not an accuracy result because
the packet distribution was synthetic.

#### Upgrade 2: labeled specialist evaluation

Use only authorized PCAPs or synthetic/lab captures and report, per threat:

- precision;
- recall;
- F1;
- false-positive rate;
- confusion matrix where appropriate;
- detection latency;
- sample count and split method.

Do not report synthetic rule-trigger counts as accuracy.

#### Upgrade 3: alert-feed investigation controls

Add dashboard filters and summaries for:

- threat class;
- severity;
- confidence threshold;
- time range;
- source/destination;
- evidence type;
- active versus acknowledged alerts.

Add a visible connection state and alert count so an operator can immediately
see whether the stream is healthy.

#### Upgrade 4: final hardening and regression pass

- Escape alert strings before inserting them into HTML.
- Test WebSocket reconnect and duplicate-alert behavior.
- Confirm HTTP polling fallback.
- Confirm capture start/stop state transitions.
- Confirm bounded flow eviction.
- Run backend syntax, diagnostics, API, and browser smoke checks.
- Record all measured results in Markdown.

### Priority 2 — Recommended for a polished prototype

#### Upgrade 5: server-side bounded alert history

Add a bounded backend history or cursor so a reconnecting dashboard can request
alerts it missed without allowing unbounded storage.

#### Upgrade 6: operational dashboard metrics

Add charts/cards for:

- packets and flows over time;
- alerts by threat class;
- severity distribution;
- probability and confidence distributions;
- processing latency;
- ignored packets caused by filters;
- active-flow count and eviction count.

#### Upgrade 7: packaging and judge-ready demonstration

Prepare:

- installation instructions;
- Npcap prerequisites;
- one safe replay command;
- one live-capture command;
- sample output;
- architecture diagram;
- limitations and safety statement;
- screenshots and a short reproducible demo script.

### Priority 3 — Data and model expansion

These are needed only if the project must provide stronger empirical coverage
across all six categories rather than a complete working prototype:

1. Add CIC-IDS2017 or another authorized labeled set for port scanning and
   infiltration/exfiltration.
2. Add DGArchive or equivalent licensed/authorized domain data for DGA
   evaluation.
3. Add authorized encrypted-malware traffic with TLS/QUIC metadata for
   fingerprint and sequence evaluation.
4. Add authorized DNS-tunnelling and beacon captures.
5. Retrain or calibrate models with capture-level or time-based splits to
   reduce leakage and improve generalization.

## 7. Recommended execution order

```text
1. Benchmark live Npcap throughput and P50/P95 latency
2. Harden and regression-test the dashboard
3. Add alert filters and connection/alert counters
4. Evaluate specialists on authorized labeled captures
5. Add server-side bounded alert history
6. Add operational charts and judge-ready packaging
7. Expand datasets only where the final scope requires it
```

## 8. Definition of “SIH-demo ready”

The project can reasonably be presented as a strong prototype when it has:

- a reproducible offline replay;
- a reproducible passive live capture demonstration;
- a documented throughput and latency benchmark;
- standardized alerts with confidence and evidence;
- a functioning dashboard and live alert stream;
- clearly labeled limitations;
- at least one authorized evaluation result for each claimed specialist;
- no claim that heuristic evidence is proof of an attack.

At the time of this document, the implementation is substantially complete,
but the formal benchmark, specialist labeled evaluation, final hardening, and
operator filtering remain.

## 9. Related documentation

- [BUILD_LOG.md](BUILD_LOG.md)
- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [stage4_classifier.md](stage4_classifier.md)
- [stage5_streaming_alerts.md](stage5_streaming_alerts.md)
- [stage8_basic_dashboard.md](stage8_basic_dashboard.md)
- [live_benign_calibration.md](live_benign_calibration.md)
- [live_port_scan_detection.md](live_port_scan_detection.md)
- [live_ddos_protocol_evidence.md](live_ddos_protocol_evidence.md)
- [live_dns_dga_detection.md](live_dns_dga_detection.md)
- [live_beacon_timing_detection.md](live_beacon_timing_detection.md)
- [live_tls_quic_detection.md](live_tls_quic_detection.md)
- [live_exfiltration_detection.md](live_exfiltration_detection.md)
