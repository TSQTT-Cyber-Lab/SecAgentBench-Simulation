"""
SecAgentBench simulation core – Monte Carlo engine (v3)
=======================================================
Manuscript: SecAgentBench as a Simulation-Based Study for Adversarial
            Robustness of LLM-Based Security Agents
Journal   : Journal of Science and Technology on Information Security

Produces (all in current working directory):
    table1_baseline_platforms.csv
    table2_isolated_attacks_simulated.csv
    table3_defense_effectiveness_simulated.csv
    table4_adaptive_attacker_simulated.csv
    table5_crosslayer_chaining_simulated.csv
    secagentbench_simulation_full_grid.csv

Usage:
    pip install numpy pandas
    python simulation_core.py

All results are SIMULATED outcomes derived from the Monte Carlo engine.
They do not represent empirical measurements on any deployed SOC system.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd


# ══════════════════════════════════════════════════════════════════════
# 1. DATACLASSES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Platform:
    """Abstract SOC platform profile."""
    name: str
    benign_acc: float          # Baseline benign-case accuracy
    coordination: float        # Coordination strictness between agents
    tool_reliability: float    # Reliability of tool layer
    base_latency: float        # Baseline latency factor (normalised to 1.0)


@dataclass
class Attack:
    """Single attack vector descriptor."""
    name: str
    layer: str                 # "Data" | "Control" | "Logic"
    severity: float            # Raw disruptive potential [0, 1]
    stealth: float             # Detection difficulty [0, 1]
    target: str                # "Triage" | "Investigation" | "Response" | "Pipeline"


@dataclass
class Defense:
    """Single defense mechanism descriptor."""
    name: str
    sensitivity: float         # Detection sensitivity [0, 1]
    mitigation: float          # Mitigation strength [0, 1]
    fp_rate: float             # False-positive rate on benign operations
    overhead: float            # Relative latency overhead factor


@dataclass
class SimulationConfig:
    """Global simulation settings."""
    n_iter: int = 500          # Monte Carlo iterations per condition
    seed: int = 42             # Random seed for reproducibility


# ══════════════════════════════════════════════════════════════════════
# 2. PARAMETERS
# ══════════════════════════════════════════════════════════════════════

PLATFORMS: Dict[str, Platform] = {
    "P1": Platform(
        name="P1",
        benign_acc=0.92,
        coordination=0.78,
        tool_reliability=0.88,
        base_latency=1.00,
    ),
    "P2": Platform(
        name="P2",
        benign_acc=0.90,
        coordination=0.82,
        tool_reliability=0.91,
        base_latency=1.10,
    ),
    "P3": Platform(
        name="P3",
        benign_acc=0.86,
        coordination=0.70,
        tool_reliability=0.83,
        base_latency=0.90,
    ),
}

ATTACKS: Dict[str, Attack] = {
    "A1_SIEM_Injection":  Attack("A1_SIEM_Injection",  "Data",    0.62, 0.72, "Triage"),
    "A2_Alert_Crafting":  Attack("A2_Alert_Crafting",  "Data",    0.58, 0.64, "Triage"),
    "A3_Context_Poison":  Attack("A3_Context_Poison",  "Data",    0.55, 0.68, "Investigation"),
    "A4_Tool_Poisoning":  Attack("A4_Tool_Poisoning",  "Control", 0.63, 0.70, "Investigation"),
    "A5_Rug_Pull":        Attack("A5_Rug_Pull",        "Control", 0.52, 0.77, "Investigation"),
    "A6_Resp_Spoofing":   Attack("A6_Resp_Spoofing",   "Control", 0.60, 0.66, "Investigation"),
    "A7_Collusion":       Attack("A7_Collusion",       "Logic",   0.57, 0.74, "Pipeline"),
    "A8_Priv_Escalation": Attack("A8_Priv_Escalation", "Logic",   0.61, 0.62, "Response"),
    "A9_Goal_Hijacking":  Attack("A9_Goal_Hijacking",  "Logic",   0.59, 0.69, "Pipeline"),
}

DEFENSES: Dict[str, Defense] = {
    "None":                     Defense("None",                     0.00, 0.00, 0.000, 0.000),
    "D1_Input_Sanitization":    Defense("D1_Input_Sanitization",    0.48, 0.30, 0.050, 0.080),
    "D2_Tool_Attestation":      Defense("D2_Tool_Attestation",      0.55, 0.42, 0.019, 0.060),
    "D3_Response_Verification": Defense("D3_Response_Verification", 0.51, 0.36, 0.032, 0.100),
    "D4_Agent_Isolation":       Defense("D4_Agent_Isolation",       0.44, 0.33, 0.022, 0.070),
    "D5_Consensus_Protocol":    Defense("D5_Consensus_Protocol",    0.58, 0.39, 0.061, 0.160),
    "D6_Behavioral_Monitor":    Defense("D6_Behavioral_Monitor",    0.46, 0.28, 0.041, 0.050),
    "Bundle_D1_D3_D4_D6":       Defense("Bundle_D1_D3_D4_D6",       0.78, 0.67, 0.094, 0.260),
    "Bundle_All":               Defense("Bundle_All",               0.89, 0.79, 0.121, 0.430),
}

ATTACKER_LEVELS: Dict[str, float] = {
    "Static":        0.00,
    "Defense_Aware": 0.08,
    "Adaptive":      0.16,
}

WORKLOADS: Dict[str, float] = {
    "Low":    0.00,
    "Medium": 0.05,
    "High":   0.11,
}

# Cross-layer chains: (label, [attack_key_1, attack_key_2, attack_key_3])
CHAINS: List[Tuple[str, List[str]]] = [
    ("A1->A4->A8", ["A1_SIEM_Injection", "A4_Tool_Poisoning",  "A8_Priv_Escalation"]),
    ("A3->A6->A9", ["A3_Context_Poison", "A6_Resp_Spoofing",   "A9_Goal_Hijacking"]),
    ("A2->A4->A9", ["A2_Alert_Crafting", "A4_Tool_Poisoning",  "A9_Goal_Hijacking"]),
]


# ══════════════════════════════════════════════════════════════════════
# 3. HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def _layer_bonus(layer: str) -> float:
    """Small additive bonus per attack layer."""
    return {"Data": 0.03, "Control": 0.04, "Logic": 0.05}.get(layer, 0.0)


def _compute_detect_prob(
    attack: Attack,
    defense: Defense,
    k_delta: float,
) -> float:
    """
    Probability that the defense detects the attack before or during
    execution.  Higher attacker knowledge (k_delta) reduces detection.
    """
    base = defense.sensitivity * (1.0 - attack.stealth)

    # Layer-aligned defense bonuses
    if attack.layer == "Logic" and "Behavioral" in defense.name:
        base += 0.08
    if attack.layer == "Control" and any(
        x in defense.name for x in ["Tool", "Response", "Bundle"]
    ):
        base += 0.07
    if attack.layer == "Data" and any(
        x in defense.name for x in ["Input", "Bundle"]
    ):
        base += 0.05

    # Adaptive attacker erodes detection
    base -= 0.5 * k_delta

    return float(np.clip(base, 0.0, 0.98))


# ══════════════════════════════════════════════════════════════════════
# 4. CORE SIMULATION
# ══════════════════════════════════════════════════════════════════════

def simulate_condition(
    platform: Platform,
    attack: Attack,
    defense: Defense,
    attacker_name: str,
    k_delta: float,
    workload_name: str,
    w_delta: float,
    cfg: SimulationConfig,
) -> Dict:
    """
    Run N Monte Carlo trials for a single (P, A, D, K, W) condition.
    Returns a dict of aggregated metrics.
    """
    rng = np.random.default_rng(cfg.seed)

    # ── Composite base risk ──────────────────────────────────────────
    base_risk = (
        attack.severity
        + (1.0 - platform.benign_acc)       * 0.35
        + (1.0 - platform.coordination)     * 0.18
        + (1.0 - platform.tool_reliability) * 0.14
        + k_delta
        + w_delta
    )
    lb = _layer_bonus(attack.layer)
    dp = _compute_detect_prob(attack, defense, k_delta)

    # ── Per-trial accumulators ───────────────────────────────────────
    succ_list:  List[bool]  = []
    det_list:   List[bool]  = []
    fp_list:    List[bool]  = []
    pep_list:   List[bool]  = []
    asup_list:  List[bool]  = []
    lat_list:   List[float] = []

    for _ in range(cfg.n_iter):

        # Detection
        detected = bool(rng.random() < dp)
        det_list.append(detected)

        # Mitigation (partial if undetected)
        mitig = defense.mitigation * (1.0 if detected else 0.45)

        # Per-trial attack success rate
        noise = float(rng.normal(0.0, 0.035))
        asr_i = float(np.clip(base_risk + lb - mitig + noise, 0.01, 0.99))
        succ_list.append(bool(rng.random() < asr_i))

        # Defense false positive on benign operation
        fp_list.append(bool(rng.random() < defense.fp_rate * (1.0 + w_delta)))

        # Privilege escalation probability
        if attack.target in {"Response", "Pipeline"}:
            mult = 0.55 if attack.layer == "Logic" else 0.25
            pep_p = float(np.clip(asr_i * mult, 0.0, 0.95))
            pep_list.append(bool(rng.random() < pep_p))
        else:
            pep_list.append(False)

        # Alert suppression (data-plane triage attacks)
        if attack.target in {"Triage", "Pipeline"} and attack.layer == "Data":
            asup_p = float(np.clip(asr_i * 0.72, 0.0, 0.95))
            asup_list.append(bool(rng.random() < asup_p))
        else:
            asup_list.append(False)

        # Latency sample
        lat_noise = float(rng.normal(0.0, 0.02))
        lat_list.append(
            platform.base_latency
            * (1.0 + defense.overhead + w_delta + lat_noise)
        )

    # ── Aggregate ────────────────────────────────────────────────────
    return {
        "Platform": platform.name,
        "Attack":   attack.name,
        "Layer":    attack.layer,
        "Defense":  defense.name,
        "Attacker": attacker_name,
        "Workload": workload_name,
        "ASR":   round(float(np.mean(succ_list)),  3),
        "DDR":   round(float(np.mean(det_list)),   3),
        "FPR_D": round(float(np.mean(fp_list)),    3),
        "PEP":   round(float(np.mean(pep_list)),   3),
        "ASupR": round(float(np.mean(asup_list)),  3),
        "DOI":   round(
            float(np.mean(lat_list)) / platform.base_latency, 3
        ),
    }


def run_full_grid(cfg: SimulationConfig) -> pd.DataFrame:
    """
    Run Monte Carlo over the full factorial grid:
    platform × attack × defense × attacker × workload.
    """
    rows: List[Dict] = []
    total = (
        len(PLATFORMS) * len(ATTACKS) * len(DEFENSES)
        * len(ATTACKER_LEVELS) * len(WORKLOADS)
    )
    done = 0

    for plat in PLATFORMS.values():
        for atk in ATTACKS.values():
            for d in DEFENSES.values():
                for att_name, k_delta in ATTACKER_LEVELS.items():
                    for wl_name, w_delta in WORKLOADS.items():
                        rows.append(simulate_condition(
                            plat, atk, d,
                            att_name, k_delta,
                            wl_name,  w_delta,
                            cfg,
                        ))
                        done += 1
                        if done % 100 == 0 or done == total:
                            print(f"    Progress: {done}/{total} conditions", end="\r")

    print()
    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════════════
# 5. TABLE GENERATORS
# ══════════════════════════════════════════════════════════════════════

def make_table1() -> pd.DataFrame:
    """
    Table 1 – Baseline platform characteristics.
    These are simulation INPUT parameters, not measured values.
    """
    rows = []
    for p in PLATFORMS.values():
        rows.append({
            "Platform":                p.name,
            "Benign_Accuracy":         p.benign_acc,
            "Coordination_Strictness": p.coordination,
            "Tool_Reliability":        p.tool_reliability,
            "Baseline_Latency":        p.base_latency,
        })
    return pd.DataFrame(rows)


def make_table2(df: pd.DataFrame) -> pd.DataFrame:
    """
    Table 2 – Isolated attack ASR per platform.
    Filter: no defense | static attacker | medium workload.
    """
    mask = (
        (df["Defense"]  == "None")
        & (df["Attacker"] == "Static")
        & (df["Workload"] == "Medium")
    )
    pivot = (
        df[mask]
        .pivot_table(index=["Attack", "Layer"], columns="Platform", values="ASR")
        .reset_index()
        .sort_values("Attack")
    )
    pivot.columns.name = None
    return pivot


def make_table3(df: pd.DataFrame) -> pd.DataFrame:
    """
    Table 3 – Defense effectiveness on Platform P2.
    Filter: Platform P2 | defense-aware attacker | medium workload.
    Columns: Defense, DDR, Residual_ASR, FPR_D, DOI.
    """
    mask = (
        (df["Platform"] == "P2")
        & (df["Attacker"] == "Defense_Aware")
        & (df["Workload"] == "Medium")
    )
    table = (
        df[mask]
        .groupby("Defense")[["DDR", "ASR", "FPR_D", "DOI"]]
        .mean()
        .round(3)
        .reset_index()
        .rename(columns={"ASR": "Residual_ASR"})
        .sort_values("Residual_ASR")
    )
    return table


def make_table4(df: pd.DataFrame) -> pd.DataFrame:
    """
    Table 4 – Adaptive attacker analysis on Platform P2.
    Filter: Platform P2 | select defenses | medium workload.
    Columns: Defense, Static, Defense_Aware, Adaptive.
    """
    keep_defs = ["None", "Bundle_D1_D3_D4_D6", "Bundle_All"]
    mask = (
        (df["Platform"] == "P2")
        & (df["Defense"].isin(keep_defs))
        & (df["Workload"] == "Medium")
    )
    pivot = (
        df[mask]
        .groupby(["Defense", "Attacker"])["ASR"]
        .mean()
        .round(3)
        .reset_index()
        .pivot(index="Defense", columns="Attacker", values="ASR")
        .reset_index()
    )
    pivot.columns.name = None

    # Guarantee column order
    for col in ["Static", "Defense_Aware", "Adaptive"]:
        if col not in pivot.columns:
            pivot[col] = float("nan")

    return pivot[["Defense", "Static", "Defense_Aware", "Adaptive"]]


def make_table5(df: pd.DataFrame, cfg: SimulationConfig) -> pd.DataFrame:
    """
    Table 5 – Cross-layer attack chaining on Platform P2.
    Implements Algorithm 2 from Appendix A.3:
        1. Simulate each constituent attack individually.
        2. Compute propagation factor from number of distinct layers.
        3. Chained ASR = clip(mean_ASR * prop_factor, 0, 0.99).
        4. CLAF = chained_ASR / mean_ASR.
        5. Joint detection = 1 - prod(1 - detect_k).
    Filter: Platform P2 | Bundle_All defense | static attacker | medium workload.
    """
    plat    = PLATFORMS["P2"]
    defense = DEFENSES["Bundle_All"]
    k_delta = ATTACKER_LEVELS["Static"]
    w_delta = WORKLOADS["Medium"]

    rows: List[Dict] = []

    for chain_label, atk_keys in CHAINS:

        # Step 1 – simulate each constituent attack individually
        indiv: List[Dict] = []
        for key in atk_keys:
            res = simulate_condition(
                plat, ATTACKS[key], defense,
                "Static", k_delta,
                "Medium", w_delta,
                cfg,
            )
            indiv.append(res)

        asr_vals = [r["ASR"] for r in indiv]
        ddr_vals = [r["DDR"] for r in indiv]
        mean_asr = float(np.mean(asr_vals))

        # Step 2 – propagation factor based on distinct layers crossed
        n_layers = len({ATTACKS[k].layer for k in atk_keys})
        prop_factor = 1.0 + 0.08 * n_layers

        # Step 3 – chained ASR
        c_asr = float(np.clip(mean_asr * prop_factor, 0.0, 0.99))

        # Step 4 – Cross-Layer Amplification Factor
        claf = round(c_asr / mean_asr, 3) if mean_asr > 0 else float("nan")

        # Step 5 – joint detection probability
        p_detect = 1.0 - math.prod(1.0 - d for d in ddr_vals)

        # Layers string  e.g. "Data-Control-Logic"
        layers_str = "-".join(ATTACKS[k].layer for k in atk_keys)

        rows.append({
            "Chain":          chain_label,
            "Layers":         layers_str,
            "Chained_ASR":    round(c_asr,    3),
            "CLAF":           claf,
            "Detection_Prob": round(p_detect, 3),
        })

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════════════
# 6. ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main() -> None:
    cfg = SimulationConfig(n_iter=500, seed=42)

    # ── Full grid ────────────────────────────────────────────────────
    print("[1/6] Running full factorial grid simulation ...")
    df = run_full_grid(cfg)
    df.to_csv("secagentbench_simulation_full_grid.csv", index=False)
    print(f"      Saved: secagentbench_simulation_full_grid.csv  ({len(df):,} rows)\n")

    # ── Table 1 ──────────────────────────────────────────────────────
    print("[2/6] Generating Table 1 – Baseline platform characteristics ...")
    t1 = make_table1()
    t1.to_csv("table1_baseline_platforms.csv", index=False)
    print("      Saved: table1_baseline_platforms.csv")
    print(t1.to_string(index=False))
    print()

    # ── Table 2 ──────────────────────────────────────────────────────
    print("[3/6] Generating Table 2 – Isolated attack effectiveness ...")
    t2 = make_table2(df)
    t2.to_csv("table2_isolated_attacks_simulated.csv", index=False)
    print("      Saved: table2_isolated_attacks_simulated.csv")
    print(t2.to_string(index=False))
    print()

    # ── Table 3 ──────────────────────────────────────────────────────
    print("[4/6] Generating Table 3 – Defense effectiveness (P2) ...")
    t3 = make_table3(df)
    t3.to_csv("table3_defense_effectiveness_simulated.csv", index=False)
    print("      Saved: table3_defense_effectiveness_simulated.csv")
    print(t3.to_string(index=False))
    print()

    # ── Table 4 ──────────────────────────────────────────────────────
    print("[5/6] Generating Table 4 – Adaptive attacker analysis (P2) ...")
    t4 = make_table4(df)
    t4.to_csv("table4_adaptive_attacker_simulated.csv", index=False)
    print("      Saved: table4_adaptive_attacker_simulated.csv")
    print(t3.to_string(index=False))
    print()

    # ── Table 5 ──────────────────────────────────────────────────────
    print("[6/6] Generating Table 5 – Cross-layer chaining (P2) ...")
    t4 = make_table4(df)
    t4.to_csv("table5_crosslayer_chaining_simulated.csv", index=False)
    print("      Saved: table5_crosslayer_chaining_simulated.csv")
    print(t3.to_string(index=False))
    print()

    print("Simulation complete.")
    print("  - secagentbench_simulation_full_grid.csv")
    print("  - table1_baseline_platforms.csv")
    print("  - table2_isolated_attacks_simulated.csv")
    print("  - table3_defense_effectiveness_simulated.csv")
    print("  - table4_adaptive_attacker_simulated.csv")
    print("  - table5_crosslayer_chaining_simulated.csv")


if __name__ == "__main__":
    main()