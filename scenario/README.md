# Scenario test — `model/model.joblib`

Loads the shipped triage artifacts (`model/model.joblib`,
`model/preprocessor.joblib`, `model/results.json`) and runs three
hand-crafted flows through the real pipeline, producing the
`triage_output` contract documented in `model/model_card.md`
(`predicted_category`, `confidence`, `risk_score`, `priority`,
`severity_score`, `recommended_action`).

## Run it

```
brew install libomp        # xgboost's native lib needs this on macOS
python3 -m pip install --break-system-packages "scikit-learn==1.6.1" xgboost matplotlib pandas
python3 scenario/run_scenarios.py
```

Outputs land in `scenario/output/`: `results.json` (full `triage_output`
per scenario), `probabilities.png`, `severity_priority.png`,
`optimization_summary.png`.

## Scenarios (`scenarios.py`)

No raw CICIDS2017 rows are available locally — the dataset is Kaggle-only
per `CLAUDE.md`, and none of the training notebooks print sample rows. The
three flows are hand-built from textbook CICIDS2017/CICFlowMeter attack
signatures, not captured data:

1. `benign_web_browse` — a short, balanced HTTPS exchange.
2. `dos_ddos_http_flood` — an application-layer flood (Hulk/GoldenEye
   style): one TCP connection hammered with ~500 near-identical small
   forward packets in under a millisecond, minimal legitimate response.
3. `slow_brute_force_ambiguous` — a low-and-slow credential-guessing
   pattern: 40 small forward/backward packets paced ~1.5s apart over 60s.

Each scenario carries an `explanation` field with the domain reasoning.

## A genuine finding, not a bug

Running these: `benign_web_browse` is correctly classified `benign` at
~100% confidence. The other two — despite being textbook-plausible attack
signatures — are also classified `benign`, at ~100% confidence.

This was investigated, not just accepted:

- `model.feature_importances_` shows the model's top splits are on
  **per-packet-length statistics** (`Bwd Packet Length Min`, `Packet
  Length Max`, `Bwd Packet Length Std`, `Fwd Packet Length Max`) and
  **flag presence** (`PSH Flag Count`, `Fwd PSH Flags`) — not on the flow
  duration / packets-per-second / byte-rate features the hand-built
  scenarios were designed around.
- The CICFlowMeter-derived flag-count columns (`SYN Flag Count`, `ACK Flag
  Count`, etc.) turned out to have mean ≈0.03–0.28 and std ≈0.02–0.45
  across the training set (checked directly against
  `preprocessor.named_steps["scale"]`) — i.e. they are near-binary
  presence indicators in real captures, not literal per-packet tallies.
  The first draft of these scenarios set them to 20/79/500 (tens to
  thousands of std deviations out of distribution) and got the same
  "benign" result, so that miscalibration was ruled out as the cause
  before drawing any conclusion — this write-up reflects the fixed
  version.
- A counterfactual search (coordinate-ascent from the training-set median
  flow, using `predict_proba` as the oracle) *does* find feature
  combinations the model confidently calls `dos_ddos` (99%+) or
  `brute_force` (94%+) — but they require pushing several tightly-coupled
  derived statistics (packet-length totals vs. per-packet mean/min/max,
  duration vs. rate) into combinations that don't correspond to any
  physically producible flow. Real CICFlowMeter output keeps those
  relationships internally consistent by construction; a hand-typed flow
  does not, by accident.

**Conclusion:** this is suggestive of a real generalization gap — the
model may be fitting narrow statistical fingerprints of the 2017 capture
files rather than a robust general notion of "flood" or "brute force" —
but it is not conclusive, since these synthetic inputs are not guaranteed
physically valid flows. It is consistent with the limitation
`model_card.md` already states ("distribution shift expected on live
networks"). The actionable next step is the same either way: validate
against flows produced by the *same* feature extractor (CICFlowMeter) on
live or replayed attack traffic, not just held-out CICIDS2017 rows drawn
from the same captures used for training/val/test.

See the console output of `run_scenarios.py` for the full "is it
optimized?" verdict (model choice, latency, tuning coverage, and this
finding).
