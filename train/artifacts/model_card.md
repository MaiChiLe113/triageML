# Model Card — SOC Triage Model `triage-xgb-1.0.0`

## Overview
This is an **ML-based SOC Triage model** for COS30018 Option D — not a final
attack detector. It estimates the likelihood that a network flow belongs to
one of seven traffic categories (benign, dos_ddos, port_scan, brute_force,
web_attack, botnet, infiltration) and produces a confidence-weighted risk
score, priority level, and recommended action. It is intended for rapid
filtering and prioritization of network flows, forwarding high-risk events —
via `session_state["triage_output"]` — to a downstream Detection LlmAgent.

**This model is intended for triage and prioritization rather than final
attack confirmation.** The Detection LlmAgent is responsible for validating
each prediction using additional context such as CTI, MITRE ATT&CK
knowledge, historical events, and further reasoning before making the final
security decision. This model provides evidence, not a verdict, and is not
responsible for final attack attribution.

## Data
- Source: dhoogla/cicids2017, Kaggle Version 2 (no-metadata parquet)
- Rows after cleaning: 2,231,795 (duplicates + constant columns removed, Inf -> NaN)
- Heartbleed rows excluded (outside the 7-class taxonomy, per spec): 11
- Features: 69 | data hash: `343dfe118f0e5417`
- Split: stratified 70/15/15, seed 42

## Method
- Preprocessing: median imputation + standard scaling, fit on train only
- Baselines: Logistic Regression, Random Forest (class-weight balanced)
- Final model: XGBoost (hist), tuned on validation with early stopping,
  refit on train+val at 300 rounds,
  params {'max_depth': 8, 'learning_rate': 0.1}, balanced sample weights

## Test results (macro F1)
| model | macro F1 |
|---|---|
| Logistic Regression | 0.3933 |
| Random Forest | 0.8798 |
| **XGBoost** | **0.9354** |

Latency: 1.797 ms/flow single,
0.0229 ms/flow batched (CPU).
Per-class metrics, PR curves and confusion matrices: see `results.json` and notebook.

## Kaggle-notebook flaws avoided
1. **Leakage via bootstrap resampling** — no resampling at all; duplicates are
   removed *before* the split so no identical flow lands in both train and
   test. Imbalance is handled with class/sample weights instead.
2. **Scaler fit on the test set** — imputer and scaler are fit on the training
   split only, then applied to val/test.
3. **CV / tuning on the test set** — hyperparameters were selected on the
   validation split; the test split was used exactly once, for final reporting.
4. **Missing random state** — seed 42 fixed for numpy, all splits and
   every model.

## Output contract
`triage_output`: event_id, predicted_category, confidence, risk_score,
priority, severity_score, recommended_action, entities, model_version.

- `predicted_category` — predicted traffic class
- `confidence` — predicted probability of the chosen class
- `risk_score` — confidence-weighted attack likelihood (here, equal to `severity_score`)
- `priority` — Low / Medium / High, derived from `severity_score` (0-1 Low, 1-3 Medium, 3-5 High)
- `severity_score` — category base severity x confidence; base severity: {'benign': 0.0, 'port_scan': 2.0, 'brute_force': 3.0, 'dos_ddos': 4.0, 'web_attack': 4.0, 'botnet': 5.0, 'infiltration': 5.0}
- `recommended_action` — "archive" / "queue_detection" / "escalate_detection", derived from `priority`
- `entities` — null for CICIDS2017 benchmark runs (populated only during live capture)
- `model_version`

## Role in the SOC pipeline
This model is the **triage stage**, not the final classifier. It filters and
prioritizes the flood of network flows so the Detection LlmAgent — which
reasons over CTI, MITRE ATT&CK knowledge, historical events, and other
context this model does not see — can focus on the events most likely to
matter. A high `risk_score` / `priority` is a request for analysis, not an
attack confirmation.

## Limitations
- Trained on 2017 benchmark traffic; distribution shift expected on live networks.
- `infiltration` has very few samples — its metrics are noisy.
- Heartbleed is not covered by the taxonomy and is not detected by this model.
- This model does not make the final security decision — its
  `predicted_category`/`risk_score`/`priority` are inputs to the downstream
  Detection LlmAgent, which must corroborate them (CTI, MITRE ATT&CK,
  historical events, reasoning) before confirming an attack.
