"""Stage 1 -> Stage 2 pipeline: PCAP packets to model-ready feature records."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from src.feature_extractor import extract_features
from src.flow_records import read_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    started = time.perf_counter()
    flows = [flow.to_dict() for flow in read_pcap(args.pcap, args.limit)]
    records = extract_features(flows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(record) for record in records) + ("\n" if records else ""))
    elapsed = time.perf_counter() - started
    print(json.dumps({
        "pcap": str(args.pcap),
        "flows": len(records),
        "elapsed_seconds": elapsed,
        "flows_per_second": len(records) / elapsed if elapsed else 0.0,
        "output": str(args.output),
    }, indent=2))


if __name__ == "__main__":
    main()
