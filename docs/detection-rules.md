# Detection Rules

> Populated in MILESTONE 10. Documents each rule: id, name, severity, thresholds, and the evidence collected.

## Design

All detection is **rule-based and explainable**. No unsubstantiated claims. Closing wording like "Possible Port Scan", "Suspicious DNS Activity", "Abnormally High Connection Rate".

Rules read from normalized packets/connections/DNS events and produce alerts with concrete `evidence`.
