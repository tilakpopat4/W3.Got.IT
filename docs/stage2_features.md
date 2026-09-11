# Stage 2 — Data Cleaning & Feature Extraction

**Code:** `src/data_clean.py`
**Input:** `C:\Users\himanshu\Downloads\CN\pcap.parquet` (455,641 × 42)
**Output:** `data/pcap_clean.parquet` (455,641 × 39), `data/label_map.json`

## What it does
1. **Drop dead/id columns** — `Arch` (all x86), `SMTP` (all 0), `IRC` (all 0), `Hash` (identifier).
2. **Replace ±inf → NaN** so they can be handled uniformly.
3. **Cap `Rate` outliers** at the 99.9th percentile (= 26,955.68); 451 rows clipped. Prevents flood artifacts from skewing scaling.
4. **Impute NaN → 0** for numeric features (1,449 cells across 37 columns). Missing stats = single-packet windows → 0 is meaningful.
5. **Encode labels** → `{Benign:0, DarkNexus:1, Gafgyt:2, Generic:3, Mirai:4, Unknown:5}`.

## Feature families (of the 37 numeric features)
- **Rate/volume:** `Rate`, `Tot sum`, `Tot size`, `AVG`, `Min`, `Max`, `Std`, `Variance`
- **TCP flags:** `syn_flag_number`, `ack_flag_number`, `rst_flag_number`, `fin_flag_number`, `psh/ece/cwr`, plus counts `syn_count`, `ack_count`, `rst_count`, `fin_count`
- **Protocol one-hots:** `TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP, DHCP, Telnet, IGMP, IPv, LLC`
- **Timing:** `IAT` (inter-arrival time), `Number`, `Header_Length`, `Time_To_Live`, `Protocol Type`

## Result
Clean, numeric, no NaN/inf. Verified by audit (`reports/audit.txt`): 0 NaN, 0 inf, no constant columns.

## Known caveat
Rows are **pre-aggregated flow-window summaries in arbitrary order** — not a time-ordered per-source stream. This matters for Stage 3 (Kalman needs ordering) and is addressed by the Stage 0–1 replay.
