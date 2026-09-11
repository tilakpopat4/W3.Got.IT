# Live botnet beacon-timing evidence

The live adapter now checks whether a flow repeats at a stable interval, a
metadata-only signal that can support botnet C2 beaconing investigations.

## Evidence rule

A flow needs at least six positive inter-arrival samples. The mean interval
must be between 0.5 and 60 seconds, and the coefficient of variation
(standard deviation divided by mean) must be at most 0.15.

Flagged evidence reports the sample count, mean interval, jitter, and
coefficient of variation. It does not inspect payloads or claim that periodic
traffic is definitely malicious; software updates, keepalives, and monitoring
agents can also be periodic.

## Boundary

This is live-only specialist evidence. It is combined with the existing
classifier, Kalman, DNS, port-scan, and volumetric signals. Offline parsers,
models, and replay outputs remain unchanged.
