# Stage 8 — Basic PCAP Analysis Dashboard

## Purpose

This build adds a local, read-only dashboard for validating the pipeline
against a saved capture or live traffic. The operator can upload a `.pcap` or
`.pcapng` file, or enter a capture interface and watch decisions update once
per second.

## Execution path

```text
Browser upload
  -> FastAPI endpoint
  -> Scapy PCAP reader
  -> bidirectional flow records
  -> numeric feature extraction
  -> Kalman anomaly update
  -> XGBoost probability
  -> JSON report
  -> dashboard table and summary
```

The endpoint never transmits packets, probes an address, decrypts payloads, or
issues blocking commands. It only reads the uploaded capture into a temporary
file and deletes that file after analysis.

## Live mode

Live mode uses Scapy's `AsyncSniffer` with the installed Windows Npcap driver.
Each observed packet updates its bidirectional flow, recomputes metadata-only
features, applies the Kalman update, and runs the selected classifier. The UI
polls the status endpoint every second and shows the latest flow decisions.
Active flows expire after 60 seconds without a packet, and the session keeps at
most 5,000 active flows. The status response reports packets observed, active
flows, expired/evicted flows, capture start time, and the timestamp of the last
packet. This prevents an unattended interface from growing memory without
boundaries and makes an empty capture distinguishable from a working capture.

On Windows:

1. Install **Npcap** (Wireshark's installer can install it).
2. Run the terminal hosting Uvicorn with capture permission, usually
   Administrator.
3. Select an active adapter from the interface suggestions. The UI shows the
   friendly Windows adapter name and status, while it sends the underlying
   `\Device\NPF_{...}` value to Scapy.
4. Select a model and click **Start live analysis**.
5. Click **Stop live analysis** when finished.

The dashboard does not need `tshark` for this mode. Wireshark is useful for
finding the correct interface and independently inspecting a saved capture;
Npcap is the Windows capture driver used by the live reader.

If the packet count remains zero, stop the session and choose the adapter
whose status is `active` and which has the current Wi-Fi/Ethernet connection.
VirtualBox, WSL, VPN, disconnected Ethernet, and loopback adapters may be
valid capture devices but will not carry ordinary Internet traffic.

The optional **Website IP filter** accepts comma-separated IPv4 or IPv6
addresses. Capture still listens passively on the selected adapter, but only
flows containing one of those addresses are sent to flow reconstruction and
model scoring. The status reports total packets observed, packets analyzed,
and packets ignored by the filter. Resolve a website first with
`Resolve-DnsName`, then enter its returned `A` or `AAAA` records. IPv6
endpoints are displayed with brackets around the address and port.

Uploaded-PCAP and live status responses also expose an `alerts` array using
the validated `ThreatAlert` contract already used by streaming replay. Each
alert includes a UTC timestamp, flow ID, threat class, fused confidence,
severity, anomaly information, model name, and evidence. Existing `flows`
records remain available for detailed dashboard rendering.

The live dashboard also opens `/ws/live-alerts` after capture starts. The
read-only WebSocket sends new alerts immediately and sends a status snapshot
four times per second. One-second HTTP polling remains as a compatibility
fallback and for capture controls.

The dashboard keeps up to 100 recent WebSocket alerts in a dedicated live
alert feed. Each entry shows threat class, severity, reason, timestamp, flow
ID, and confidence. The feed can be cleared without changing capture state.

### Offline path protection

Live acquisition changes are isolated to the live adapter and dashboard
integration. The existing saved-PCAP/Parquet parsers, ordered replay,
feature/model artifacts, and offline report formats remain unchanged. If a
shared helper must change in the future, its offline behavior must be
regression-tested before the live change is accepted.

## Meaning of a flag

The dashboard uses the following explainable decision chain:

1. Extract metadata-only flow features.
2. Run the selected XGBoost model and obtain a probability from 0 to 1.
3. Flag the flow when the probability is greater than or equal to the
   operator-selected threshold.
4. Update the Kalman filter for rate, inter-arrival time, and SYN count.
5. Fuse the scores:

   ```text
   confidence = 0.7 * classifier_probability
              + 0.3 * bounded_kalman_anomaly
   ```

6. Aggregate flows by destination before making a possible DoS/DDoS
   assessment. A single flagged flow is not automatically DoS or DDoS.

The current implementation supports generic malicious-flow scoring, the
specialized Mythic HTTP C2 model, packet-volume evidence, destination
aggregation, live port-scan evidence, and live SYN/UDP flood evidence.
It also adds live DNS/DGA metadata evidence, botnet beacon-timing evidence,
and TLS/QUIC metadata anomaly evidence, plus directional exfiltration
evidence;
the full DNS query name is
omitted from alert evidence.
JSONL replay, WebSocket alert streaming,
timing scoring remains
planned extensions, not current detector claims.

## Model selection and live interface

The **Generic flow model** is the broad benign/malicious flow model. It is
appropriate for general traffic experiments but does not prove DDoS.

The **Mythic HTTP C2 model** is specialized for the TQH Mythic Poseidon
HTTP command-and-control distribution. It should not be used to classify
ordinary websites as malicious or benign with production confidence.

The **Live interface** is an Npcap/Scapy capture device. The backend reads
packets from that interface, groups them into in-memory bidirectional flows,
updates features and models, and sends metadata summaries to the browser.
It is passive: it does not transmit, probe, decrypt, or block traffic.

## Run

From the repository root:

```powershell
python -m uvicorn src.dashboard_api:app --reload
```

Open `http://127.0.0.1:8000`.

Use `Generic flow model` for the original generic flow detector. Use
`Mythic HTTP C2 model` for TQH Poseidon-style HTTP C2 captures. The Mythic
model is not a general verdict for every HTTP website; it is specialized for
the TQH Mythic distribution.

## Dashboard output

- Total flows reconstructed
- Optional packet read limit for quick smoke tests
- Flagged flows and flag rate
- Processing throughput
- Live packets observed, active flows, and last-packet timestamp
- Selected model and threshold
- Per-flow probability
- Source/destination addresses and ports
- Protocol, packet count, byte count
- Kalman anomaly level and score
- Clear/flagged decision
- Exact UTC start/end timeline for each flow
- Observed first-packet direction, separate from canonical flow identity
- Classifier flag reason, top model features, packet rate, and Kalman inputs
- Fused confidence and severity
- Destination aggregation showing packet volume, distinct sources, and a
  cautious `none`, `possible_dos`, or `possible_ddos` assessment
- Client-side investigation filters across all displayed fields, including
  packet count, byte count, probability, status, severity, anomaly, IPs,
  ports, protocol, timestamps, reasons, and top feature values

## Understanding a flag

The current detector uses **XGBoost gradient-boosted decision trees**, not a
Random Forest. The dashboard reports the probability and threshold comparison
that caused each flag. The Kalman layer is shown separately: it analyzes the
flow's rate, inter-arrival time, and SYN count for abnormal behavior; it does
not itself decide the malicious class.

The flow table distinguishes:

- **Observed source/destination:** direction of the first packet seen.
- **Canonical flow endpoints:** the normalized pair used to combine both
  directions into one flow.

Therefore the displayed source is now the actual first observed sender, while
the flow identifier remains bidirectionally stable. A flagged flow does not
mean that the source IP alone is malicious; it means the complete flow's
metadata pattern crossed the selected model threshold.

Stage 5 now fuses classifier probability with a bounded Kalman anomaly
component:

```text
confidence = 0.7 * classifier_probability
           + 0.3 * bounded_kalman_anomaly
```

The dashboard does not call a 3-packet flow DoS/DDoS. Volumetric assessment
requires at least 1,000 packets and 1,000 packets/sec; DDoS additionally
requires at least three distinct sources targeting the same destination. These
are conservative demo thresholds, not universal attack definitions.

## DDoS terminology

DoS is an attack against one target, while DDoS uses many distributed sources
against one target. This dashboard should not label ordinary classifier flags as
DDoS. The current generic model reports `malicious` only; a dedicated DDoS
classifier and fan-in/fan-out aggregation are required before claiming a
flow is DDoS traffic.

## Wireshark versus tshark

Install Wireshark if you want a desktop packet inspector and visual packet
debugging. Its bundled `tshark` is useful for command-line packet summaries
and capture validation. The dashboard does not require either tool: it uses
the Python Scapy reader already used by the project, which keeps the test
path identical to the backend pipeline. Wireshark/tshark can be used
alongside this dashboard to inspect why a particular flow was reconstructed.

## Known limitations

The current live reader keeps active flows in memory and updates a flow on
every packet. It does not yet expire idle flows, persist results in SQLite,
stream live WebSocket updates, or display raw HTTP/TLS metadata. Those are
subsequent backend stages.
