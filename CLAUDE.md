# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

COS30018 Option D — SOC Triage ML pipeline. Classical-ML classifier that
triages CICIDS2017 network flows into 7 attack categories and emits a
`triage_output` dict consumed downstream (via `session_state["triage_output"]`)
by a Detection LlmAgent. This repo is currently notebook-only; there is no
package/CLI code yet.

## Repo layout

- `data/prepare.ipynb` — Step 1, runs on **Google Colab**. Loads the
  `dhoogla/cicids2017` Kaggle dataset (Version 2, no-metadata parquet),
  verifies schema, groups raw labels into the 7 categories, writes
  `data/manifest.json`. Does **not** split, scale, impute, or train.
- `train/triage.ipynb` — Step 2, runs on **Kaggle** (needs the dataset
  attached as a notebook input at `/kaggle/input`). Full pipeline: cleaning,
  label engineering, stratified split, imputation/scaling, baseline models
  (LogReg, RandomForest), tuned XGBoost, evaluation, SHAP explainability,
  output-contract construction, and export of `model.joblib`,
  `preprocessor.joblib`, `results.json`, `model_card.md`.
- `train/` currently has uncommitted local content beyond `triage.ipynb`
  (see `git status`) — check before assuming the working tree matches HEAD.

There is no build/lint/test tooling in this repo (no `package.json`,
`requirements.txt`, or test suite) — everything runs by executing notebook
cells top-to-bottom in their respective hosted environment (Colab or Kaggle).

## Dataset access — do not use kagglehub

`kagglehub.dataset_download(...)` returns a 403 in both the Colab and Kaggle
environments used for this project. The dataset must instead be attached via
the platform's UI (Colab's Kaggle "Data Explorer" panel, or Kaggle's notebook
"Add Input"), and the notebooks discover the mounted parquet path by
searching known roots (`/kaggle/input`, `/content/kaggle/input`, `/content`)
— never hardcode a mount path.

## Fixed schema contract

These constants are locked across both notebooks and must stay consistent:

- `EXPECTED_N_FEATURES = 77` — the dhoogla v2 no-metadata parquet already
  strips 7 metadata columns + 1 zero-variance column from the original
  78-79 column CICIDS2017 schema.
- `LABEL_COL` — resolved against known variants (`"Label"`, `" Label"`),
  never assumed.
- `CATEGORIES = ["benign", "dos_ddos", "port_scan", "brute_force",
  "web_attack", "botnet", "infiltration"]` — the canonical 7-class taxonomy
  and category order, fixed by the project spec.
- Label-to-category mapping uses keyword matching (not exact equality) to
  survive CICIDS2017's en-dash/space/case variants across daily capture
  files. Order matters: `"web attack"` must be checked before `"brute"`
  (e.g. `"Web Attack - Brute Force"` must map to `web_attack`).
- `Heartbleed` does not map to any of the 7 categories. This is expected and
  correct — it must halt the notebook / be explicitly quarantined
  (`ACKNOWLEDGE_HEARTBLEED` gate in `train/triage.ipynb`), never silently
  bucketed or dropped.

## STOP-gate design pattern (important — do not "fix" these)

Both notebooks are deliberately built around STOP gates that halt execution
with a full diagnostic dump rather than silently working around a problem:

1. **Schema gate** — feature-column count must equal exactly 77; any
   mismatch halts with the full column list printed.
2. **Label gate** — every raw label must map to one of the 7 categories.
   Heartbleed is expected to fail this and halt (report it, don't bucket or
   drop it).
3. **Leakage guard** — no flow id / IP / port / timestamp / label-derived
   column may survive into the feature set.

If a gate fires, the correct action is to stop and report the printed
output — **not** to edit the gate to make it pass. When modifying these
notebooks, preserve this fail-loud-and-report behavior; don't add silent
fallbacks, defaults, or `try/except` that swallow these conditions.

## ML methodology conventions (train/triage.ipynb)

Follow these when touching the training notebook — they encode specific
anti-leakage lessons the project is graded on:

- Drop duplicate rows and constant columns **before** the train/val/test
  split (never resample/bootstrap, which would leak identical flows across
  splits — imbalance is handled via class/sample weights instead).
- Imputation and scaling (`SimpleImputer` + `StandardScaler`) are fit on the
  **train split only**, then applied to val/test. A `FITTING_ALLOWED` flag
  is asserted before every `.fit()` call and only flips to `True` after the
  split cell runs — keep this guard when adding new fit steps.
- Split is stratified 70/15/15 with `SEED = 42` used everywhere (numpy,
  random, all splits, all models).
- Hyperparameter tuning (XGBoost grid over `max_depth` x `learning_rate`,
  with early stopping) happens on the **validation** split only. The final
  model is refit on train+val at the best iteration count. The **test**
  split is touched exactly once, for final reporting.
- Final XGBoost model is trained with `device="cuda"` if available but reset
  to `device="cpu"` before export, matching SOC (CPU) deployment.

## Output contract

`build_triage_output()` in `train/triage.ipynb` (§13) defines the schema
handed to the downstream Detection LlmAgent:

```
{
  "event_id": str,
  "category": one of CATEGORIES,
  "confidence": float,
  "severity_score": SEVERITY_BASE[category] * confidence,
  "entities": {"src_ip", "dst_ip", "dst_port", "protocol"},  # always null for CICIDS2017 runs
  "model_version": str,
}
```

`entities` is always `null` for CICIDS2017 benchmark runs specifically
because the no-metadata parquet files never contain IP/port/flow-id columns
— it is only populated during live traffic capture (a later, not-yet-built
step). Keep this field null rather than inferring/stubbing values when
working with the benchmark dataset.

## Working with these notebooks

- Notebooks are meant to be run top-to-bottom in their target hosted
  environment (Colab for `prepare.ipynb`, Kaggle for `triage.ipynb`); they
  are not designed to run locally without the dataset attached.
- When asked to modify a notebook, edit the `.ipynb` JSON directly (or via
  a notebook-editing tool) — there is no `.py` mirror to edit instead.
- Both notebooks print extensive diagnostic output by design (per-file
  shapes/columns on load, full column dumps on gate failure, tuning logs,
  etc.) — preserve this when refactoring, since the project workflow is
  "run it, then paste the output back for review" (see the bottom of
  `data/prepare.ipynb`).
