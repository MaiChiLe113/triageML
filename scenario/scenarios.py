"""Synthetic scenario inputs for the shipped triage model (model/model.joblib).

No raw CICIDS2017 rows are available locally (the dataset is Kaggle-only,
per CLAUDE.md), so these three flows are hand-crafted from known CICIDS2017
flow-feature signatures for each traffic pattern, not captured/real data.
Feature keys and order must exactly match model/results.json["feature_cols"].
"""

SCENARIOS = [
    {
        "name": "benign_web_browse",
        "expected_category": "benign",
        "explanation": (
            "A short HTTPS request/response over TCP: balanced forward/backward "
            "packet counts and byte volumes, a handful of PSH/ACK flags, one "
            "clean SYN/FIN pair, moderate inter-arrival times, and no repeated "
            "single-port hammering or flood-scale packet rate. None of the "
            "scan/flood/brute-force signatures below are present."
        ),
        "features": {
            "Protocol": 6, "Flow Duration": 850000, "Total Fwd Packets": 12,
            "Total Backward Packets": 14, "Fwd Packets Length Total": 1800,
            "Bwd Packets Length Total": 9200, "Fwd Packet Length Max": 517,
            "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 150.0,
            "Fwd Packet Length Std": 120.0, "Bwd Packet Length Max": 1460,
            "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 657.1,
            "Bwd Packet Length Std": 480.0, "Flow Bytes/s": 12941.2,
            "Flow Packets/s": 30.6, "Flow IAT Mean": 32692.3,
            "Flow IAT Std": 45000.0, "Flow IAT Max": 210000, "Flow IAT Min": 20,
            "Fwd IAT Total": 820000, "Fwd IAT Mean": 74545.5,
            "Fwd IAT Std": 50000, "Fwd IAT Max": 200000, "Fwd IAT Min": 30,
            "Bwd IAT Total": 800000, "Bwd IAT Mean": 61538.5,
            "Bwd IAT Std": 48000, "Bwd IAT Max": 195000, "Bwd IAT Min": 25,
            "Fwd PSH Flags": 3, "Fwd URG Flags": 0, "Fwd Header Length": 240,
            "Bwd Header Length": 280, "Fwd Packets/s": 14.1,
            "Bwd Packets/s": 16.5, "Packet Length Min": 0,
            "Packet Length Max": 1460, "Packet Length Mean": 423.1,
            "Packet Length Std": 410.0, "Packet Length Variance": 168100.0,
            "FIN Flag Count": 1, "SYN Flag Count": 1, "RST Flag Count": 0,
            "PSH Flag Count": 1, "ACK Flag Count": 1, "URG Flag Count": 0,
            "CWE Flag Count": 0, "ECE Flag Count": 0, "Down/Up Ratio": 1.2,
            "Avg Packet Size": 423.1, "Avg Fwd Segment Size": 150.0,
            "Avg Bwd Segment Size": 657.1, "Subflow Fwd Packets": 12,
            "Subflow Fwd Bytes": 1800, "Subflow Bwd Packets": 14,
            "Subflow Bwd Bytes": 9200, "Init Fwd Win Bytes": 29200,
            "Init Bwd Win Bytes": 28960, "Fwd Act Data Packets": 8,
            "Fwd Seg Size Min": 20, "Active Mean": 500000, "Active Std": 30000,
            "Active Max": 540000, "Active Min": 460000, "Idle Mean": 0,
            "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,
        },
    },
    {
        "name": "dos_ddos_http_flood",
        "expected_category": "dos_ddos",
        "explanation": (
            "An application-layer flood (Hulk/GoldenEye-style, as represented "
            "in CICIDS2017): a single TCP connection (one SYN) flooded with "
            "~500 near-identical small forward packets in under a millisecond, "
            "with essentially no legitimate backward response, and an extreme "
            "Flow/Fwd Packets-per-second rate that no normal client-server "
            "exchange produces. TCP flag *counts* are kept near their normal "
            "0/1 range (they mark flag presence, not packet volume, in this "
            "dataset) so the packet-rate/duration/byte-rate features carry "
            "the flood signal."
        ),
        "features": {
            "Protocol": 6, "Flow Duration": 900, "Total Fwd Packets": 500,
            "Total Backward Packets": 2, "Fwd Packets Length Total": 24000,
            "Bwd Packets Length Total": 0, "Fwd Packet Length Max": 48,
            "Fwd Packet Length Min": 48, "Fwd Packet Length Mean": 48.0,
            "Fwd Packet Length Std": 0.0, "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0, "Flow Bytes/s": 26666666.7,
            "Flow Packets/s": 557777.8, "Flow IAT Mean": 1.8,
            "Flow IAT Std": 0.5, "Flow IAT Max": 5, "Flow IAT Min": 0,
            "Fwd IAT Total": 900, "Fwd IAT Mean": 1.8, "Fwd IAT Std": 0.4,
            "Fwd IAT Max": 4, "Fwd IAT Min": 0, "Bwd IAT Total": 900,
            "Bwd IAT Mean": 450, "Bwd IAT Std": 0, "Bwd IAT Max": 900,
            "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Fwd URG Flags": 0,
            "Fwd Header Length": 10000, "Bwd Header Length": 40,
            "Fwd Packets/s": 555555.6, "Bwd Packets/s": 2222.2,
            "Packet Length Min": 0, "Packet Length Max": 48,
            "Packet Length Mean": 47.8, "Packet Length Std": 2.0,
            "Packet Length Variance": 4.0, "FIN Flag Count": 0,
            "SYN Flag Count": 1, "RST Flag Count": 0, "PSH Flag Count": 1,
            "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0,
            "ECE Flag Count": 0, "Down/Up Ratio": 0.0, "Avg Packet Size": 47.8,
            "Avg Fwd Segment Size": 48.0, "Avg Bwd Segment Size": 0.0,
            "Subflow Fwd Packets": 500, "Subflow Fwd Bytes": 24000,
            "Subflow Bwd Packets": 2, "Subflow Bwd Bytes": 0,
            "Init Fwd Win Bytes": 8192, "Init Bwd Win Bytes": -1,
            "Fwd Act Data Packets": 0, "Fwd Seg Size Min": 20,
            "Active Mean": 900, "Active Std": 0, "Active Max": 900,
            "Active Min": 900, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0,
            "Idle Min": 0,
        },
    },
    {
        "name": "slow_brute_force_ambiguous",
        "expected_category": "brute_force",
        "explanation": (
            "A deliberately low-and-slow credential-guessing pattern (e.g. SSH "
            "login attempts paced ~1.5s apart to evade rate-based detection): "
            "40 small forward packets and 40 small backward rejections over a "
            "full 60-second flow, one connection (single SYN, normal flag "
            "presence) but low Flow Bytes/s combined with a long duration and "
            "large, regularly-spaced Fwd/Bwd inter-arrival times from the "
            "repeated attempt/reject cycle. This sits between 'quiet normal "
            "traffic' and 'brute force' in feature space, unlike the flood "
            "signature above, so it's the scenario most likely to produce a "
            "lower-confidence, 'needs review' style prediction."
        ),
        "features": {
            "Protocol": 6, "Flow Duration": 60000000, "Total Fwd Packets": 40,
            "Total Backward Packets": 40, "Fwd Packets Length Total": 2400,
            "Bwd Packets Length Total": 3200, "Fwd Packet Length Max": 64,
            "Fwd Packet Length Min": 56, "Fwd Packet Length Mean": 60.0,
            "Fwd Packet Length Std": 3.0, "Bwd Packet Length Max": 88,
            "Bwd Packet Length Min": 72, "Bwd Packet Length Mean": 80.0,
            "Bwd Packet Length Std": 4.0, "Flow Bytes/s": 93.3,
            "Flow Packets/s": 1.33, "Flow IAT Mean": 759493.7,
            "Flow IAT Std": 150000, "Flow IAT Max": 1500000,
            "Flow IAT Min": 200000, "Fwd IAT Total": 59000000,
            "Fwd IAT Mean": 1512820.5, "Fwd IAT Std": 180000,
            "Fwd IAT Max": 1600000, "Fwd IAT Min": 900000,
            "Bwd IAT Total": 59500000, "Bwd IAT Mean": 1525641.0,
            "Bwd IAT Std": 175000, "Bwd IAT Max": 1580000,
            "Bwd IAT Min": 950000, "Fwd PSH Flags": 0, "Fwd URG Flags": 0,
            "Fwd Header Length": 800, "Bwd Header Length": 800,
            "Fwd Packets/s": 0.67, "Bwd Packets/s": 0.67,
            "Packet Length Min": 56, "Packet Length Max": 88,
            "Packet Length Mean": 70.0, "Packet Length Std": 10.0,
            "Packet Length Variance": 100.0, "FIN Flag Count": 0,
            "SYN Flag Count": 1, "RST Flag Count": 0, "PSH Flag Count": 0,
            "ACK Flag Count": 1, "URG Flag Count": 0, "CWE Flag Count": 0,
            "ECE Flag Count": 0, "Down/Up Ratio": 1.0, "Avg Packet Size": 70.0,
            "Avg Fwd Segment Size": 60.0, "Avg Bwd Segment Size": 80.0,
            "Subflow Fwd Packets": 40, "Subflow Fwd Bytes": 2400,
            "Subflow Bwd Packets": 40, "Subflow Bwd Bytes": 3200,
            "Init Fwd Win Bytes": 29200, "Init Bwd Win Bytes": 65535,
            "Fwd Act Data Packets": 40, "Fwd Seg Size Min": 20,
            "Active Mean": 2000, "Active Std": 300, "Active Max": 2500,
            "Active Min": 1500, "Idle Mean": 1500000, "Idle Std": 200000,
            "Idle Max": 1800000, "Idle Min": 1200000,
        },
    },
]
