# SIH-145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Organization:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity
**Goal:** A streaming AI/ML pipeline that passively ingests one-way IP traffic and detects, classifies, and scores cyber threats in near real time — using metadata only, no decryption, no return path, alert-only (no blocking).

---

## Documentation index

| Doc | What it covers |
|---|---|
| [BUILD_LOG.md](BUILD_LOG.md) | Chronological log of everything built, every run, every result |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | Consolidated history, current status, limitations, and upgrade roadmap |
| [throughput_latency_benchmark.md](throughput_latency_benchmark.md) | Reproducible flow throughput and latency benchmark |
| [live_throughput_latency_benchmark.md](live_throughput_latency_benchmark.md) | Live callback and optional passive Npcap benchmark |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The full hybrid pipeline (Stages 0–6), why each stage exists |
| [stage2_features.md](stage2_features.md) | Stage 2 — data cleaning & feature extraction |
| [stage3_kalman.md](stage3_kalman.md) | Stage 3 — Kalman anomaly engine |
| [stage4_classifier.md](stage4_classifier.md) | Stage 4 — threat classifier (training, hardening, audit) |
| [datasets.md](datasets.md) | Datasets in use, coverage per threat, gaps |

---

## The 6 threat classes (from the problem statement)

| # | Threat | Detection idea | Data status |
|---|--------|----------------|-------------|
| a | Volumetric / protocol DDoS | flow-rate + source-IP entropy | ✅ covered |
| b | Botnet C2 beaconing | periodicity / inter-arrival | ✅ covered |
| c | DGA / DNS tunnelling | domain entropy / n-grams | ❌ gap |
| d | Malware in encrypted TLS/QUIC | JA3/JA4 + size/timing metadata | ❌ gap |
| e | Recon / port scanning | rolling host/port fan-out | ✅ live prototype |
| f | Data exfiltration | out:in byte-ratio anomaly | ❌ gap |

---

## Architectural constraints (must always hold)

- **Read-only ingest** — no return path, no probing, no handshake completion.
- **No payload decryption** — TLS/QUIC analysed from metadata only.
- **Streaming, not batch** — bounded-latency alerts.
- **Defined throughput target** — must state & demonstrate flows/sec.
- **Standardized alert schema** — timestamp, flow id, threat class, confidence, evidence.

## Rule
> **Every build step is documented in Markdown.** Each new module/run gets an entry in `BUILD_LOG.md` and, where relevant, its own stage doc.
