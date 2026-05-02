# Appendix – SecAgentBench Simulation Study

> **Note to readers:** This appendix is extracted from the manuscript
> "SecAgentBench as a Simulation-Based Study for Adversarial Robustness
> of LLM-Based Security Agents" and is provided as a standalone
> reproducibility reference.
>
> All results described here and in the main paper are **simulated
> outcomes** derived from `code/simulation_core.py` (v3).
> They do **not** represent empirical measurements on any deployed
> SOC system.

---

## Appendix A. Monte Carlo Simulation Procedure

### A.1 Overview

The simulation engine implements a Monte Carlo procedure over a full
factorial grid of five factors:

| Factor             | Levels                                              |
|--------------------|-----------------------------------------------------|
| Platform profile   | P1, P2, P3                                          |
| Attack type        | A1-A9 (nine attacks across three layers)            |
| Defense config     | None, D1-D6, Bundle D1+D3+D4+D6, Bundle All        |
| Attacker knowledge | Static, Defense-Aware, Adaptive                     |
| Workload intensity | Low, Medium, High                                   |

Total unique conditions: **1,215**
(3 platforms x 9 attacks x 9 defenses x 3 attacker levels x 3 workloads)

For each condition the engine runs `N_ITER = 500` independent
Monte Carlo trials with a fixed seed (`seed = 42`) and aggregates
six outcome metrics: ASR, DDR, FPR_D, PEP, ASupR, DOI.

---

### A.2 Simulation algorithm (Algorithm 1)
Algorithm 1: Monte Carlo simulation for one condition (P, A, D, K, W)

Input : Platform P, Attack A, Defense D,
Attacker knowledge delta K_delta,
Workload delta W_delta,
Number of iterations N

Output: {ASR, DDR, FPR_D, PEP, ASupR, DOI}

================================================================

SETUP

Compute base_risk:
base_risk = attack.severity

(1 - platform.benign_acc) * 0.35

(1 - platform.coordination) * 0.18

(1 - platform.tool_reliability) * 0.14

K_delta

W_delta

Compute layer_bonus:
Data -> +0.03
Control -> +0.04
Logic -> +0.05

Compute detect_prob:
base = defense.sensitivity * (1 - attack.stealth) Layer-aligned bonuses:
if layer == Logic AND "Behavioral" in defense.name -> base += 0.08
if layer == Control AND defense is Tool/Response/Bundle -> base += 0.07
if layer == Data AND defense is Input/Bundle -> base += 0.05 Adaptive attacker penalty:
base -= 0.5 * K_delta Clamp to [0.00, 0.98]

================================================================

MONTE CARLO LOOP (i = 1 ... N)

4a. detected_i ~ Bernoulli(detect_prob)

4b. mitig = defense.mitigation * (1.0 if detected_i else 0.45)

4c. noise_i ~ Normal(0, 0.035)
asr_i = clip(base_risk + layer_bonus - mitig + noise_i,
0.01, 0.99)

4d. success_i ~ Bernoulli(asr_i)

4e. fp_i ~ Bernoulli(defense.fp_rate * (1 + W_delta))

4f. Privilege escalation:
if target in {Response, Pipeline}:
mult = 0.55 if layer == Logic else 0.25
pep_p = clip(asr_i * mult, 0, 0.95)
pep_i ~ Bernoulli(pep_p)
else:
pep_i = 0

4g. Alert suppression:
if target in {Triage, Pipeline} AND layer == Data:
asup_p = clip(asr_i * 0.72, 0, 0.95)
asup_i ~ Bernoulli(asup_p)
else:
asup_i = 0

4h. Latency:
lat_noise_i ~ Normal(0, 0.02)
latency_i = platform.base_latency
* (1 + defense.overhead + W_delta + lat_noise_i)

================================================================

AGGREGATE

ASR = mean(success_i)
DDR = mean(detected_i)
FPR_D = mean(fp_i)
PEP = mean(pep_i)
ASupR = mean(asup_i)
DOI = mean(latency_i) / platform.base_latency

Return {ASR, DDR, FPR_D, PEP, ASupR, DOI}

---

### A.3 Cross-layer attack chaining (Algorithm 2)

Three representative chains are evaluated in Table 5 of the paper:

| Chain     | Constituent attacks                                            |
|-----------|----------------------------------------------------------------|
| A1->A4->A8 | A1_SIEM_Injection, A4_Tool_Poisoning, A8_Priv_Escalation     |
| A3->A6->A9 | A3_Context_Poison, A6_Resp_Spoofing, A9_Goal_Hijacking       |
| A2->A4->A9 | A2_Alert_Crafting, A4_Tool_Poisoning, A9_Goal_Hijacking      |

Evaluation condition: Platform P2, Defense Bundle_All,
Attacker = Static (K_delta = 0.00), Workload = Medium (W_delta = 0.05).
Algorithm 2: Cross-layer chaining evaluation

Input : chain = ordered list of attack keys [A_1, A_2, A_3]
Fixed condition: P2, Bundle_All, Static, Medium

Output: {chain_label, layers_str, Chained_ASR, CLAF, Detection_Prob}

================================================================

For each A_k in chain:
Run Algorithm 1 -> obtain ASR_k, DDR_k

mean_ASR = mean(ASR_k for k in chain)

n_layers = |{A_k.layer : k in chain}| (count distinct layers)
prop_factor = 1.0 + 0.08 * n_layers

Chained_ASR = clip(mean_ASR * prop_factor, 0.0, 0.99)

CLAF = Chained_ASR / mean_ASR
(values > 1.0 indicate cross-layer amplification)

Detection_Prob = 1 - prod(1 - DDR_k for k in chain)

layers_str = A_1.layer + "-" + A_2.layer + "-" + A_3.layer

Return {chain_label, layers_str, Chained_ASR, CLAF, Detection_Prob}

---

## Appendix B. Parameter Settings

### B.1 Platform profiles (Table 1 inputs)

| Parameter               |  P1  |  P2  |  P3  |
|-------------------------|-----:|-----:|-----:|
| Benign accuracy         | 0.92 | 0.90 | 0.86 |
| Coordination strictness | 0.78 | 0.82 | 0.70 |
| Tool reliability        | 0.88 | 0.91 | 0.83 |
| Baseline latency        | 1.00 | 1.10 | 0.90 |

> P1: well-coordinated, high accuracy, moderate tool reliability.  
> P2: highest tool reliability and coordination, slightly lower accuracy.  
> P3: lowest accuracy, loosest coordination, lightest latency footprint.

---

### B.2 Attack parameters (A1-A9)

| Attack                | Layer   | Severity | Stealth | Target        |
|-----------------------|---------|----------|---------|---------------|
| A1: SIEM Injection    | Data    |   0.62   |  0.72   | Triage        |
| A2: Alert Crafting    | Data    |   0.58   |  0.64   | Triage        |
| A3: Context Poisoning | Data    |   0.55   |  0.68   | Investigation |
| A4: Tool Poisoning    | Control |   0.63   |  0.70   | Investigation |
| A5: Rug Pull          | Control |   0.52   |  0.77   | Investigation |
| A6: Response Spoofing | Control |   0.60   |  0.66   | Investigation |
| A7: Collusion         | Logic   |   0.57   |  0.74   | Pipeline      |
| A8: Privilege Escal.  | Logic   |   0.61   |  0.62   | Response      |
| A9: Goal Hijacking    | Logic   |   0.59   |  0.69   | Pipeline      |

**Severity**: raw disruptive potential before defense and platform
effects are applied.  
**Stealth**: detection difficulty (higher = harder to detect).  
**Target**: primary agent stage affected by the attack.

---

### B.3 Defense parameters (D1-D6 and bundles)

| Defense                | Sensitivity | Mitigation | FP rate | Overhead |
|------------------------|------------:|-----------:|--------:|---------:|
| D1: Input Sanitization |    0.48     |    0.30    |  0.050  |  0.080   |
| D2: Tool Attestation   |    0.55     |    0.42    |  0.019  |  0.060   |
| D3: Resp. Verification |    0.51     |    0.36    |  0.032  |  0.100   |
| D4: Agent Isolation    |    0.44     |    0.33    |  0.022  |  0.070   |
| D5: Consensus Protocol |    0.58     |    0.39    |  0.061  |  0.160   |
| D6: Behavioral Monitor |    0.46     |    0.28    |  0.041  |  0.050   |
| Bundle D1+D3+D4+D6     |    0.78     |    0.67    |  0.094  |  0.260   |
| Bundle All             |    0.89     |    0.79    |  0.121  |  0.430   |

> Bundle values reflect partial redundancy and interaction effects,
> not the arithmetic sum of individual defense parameters.

---

### B.4 Attacker knowledge levels

| Level         | K_delta | Description                                         |
|---------------|--------:|-----------------------------------------------------|
| Static        |  +0.00  | Unaware of deployed defenses                        |
| Defense_Aware |  +0.08  | Knows defense categories but not exact parameters   |
| Adaptive      |  +0.16  | Fully aware; optimizes payload for deployed defense |

---

### B.5 Workload intensity levels

| Level  | W_delta | Effect on base risk and FPR-D           |
|--------|--------:|-----------------------------------------|
| Low    |  +0.00  | Baseline                                |
| Medium |  +0.05  | Moderate increase in FP and latency     |
| High   |  +0.11  | Notable increase in FP and latency      |

---

## Appendix C. Reproducibility Artifacts

### C.1 Execution environment

| Component   | Version |
|-------------|---------|
| Python      | 3.11+   |
| numpy       | 1.26+   |
| pandas      | 2.2+    |
| matplotlib  | 3.8+    |
| python-docx | 1.1+    |

Install all dependencies:

```bash
pip install numpy pandas matplotlib python-docx
```

---

### C.2 Running the simulation

```bash
cd code
python simulation_core.py
```

Expected terminal output:
[1/6] Running full factorial grid simulation ...
Progress: 1215/1215 conditions
Saved: secagentbench_simulation_full_grid.csv (1,215 rows)

[2/6] Generating Table 1 - Baseline platform characteristics ...
Saved: table1_baseline_platforms.csv

[3/6] Generating Table 2 - Isolated attack effectiveness ...
Saved: table2_isolated_attacks_simulated.csv

[4/6] Generating Table 3 - Defense effectiveness (P2) ...
Saved: table3_defense_effectiveness_simulated.csv

[5/6] Generating Table 4 - Adaptive attacker analysis (P2) ...
Saved: table4_adaptive_attacker_simulated.csv

[6/6] Generating Table 5 - Cross-layer attack chaining (P2) ...
Saved: table5_crosslayer_chaining_simulated.csv

============================================================
All tables generated successfully.
============================================================
Output files:
secagentbench_simulation_full_grid.csv
table1_baseline_platforms.csv
table2_isolated_attacks_simulated.csv
table3_defense_effectiveness_simulated.csv
table4_adaptive_attacker_simulated.csv
table5_crosslayer_chaining_simulated.csv

---

### C.3 Output file descriptions

| Output file                                  | Paper ref. | Description                               |
|----------------------------------------------|------------|-------------------------------------------|
| `secagentbench_simulation_full_grid.csv`     | —          | Full 1,215-row factorial grid             |
| `table1_baseline_platforms.csv`              | Table 1    | Platform input parameters                 |
| `table2_isolated_attacks_simulated.csv`      | Table 2    | ASR per attack per platform (no defense)  |
| `table3_defense_effectiveness_simulated.csv` | Table 3    | DDR, Residual ASR, FPR_D, DOI on P2      |
| `table4_adaptive_attacker_simulated.csv`     | Table 4    | ASR under Static/Aware/Adaptive on P2    |
| `table5_crosslayer_chaining_simulated.csv`   | Table 5    | Chained ASR, CLAF, Detection probability  |

---

### C.4 Random seed and stochastic stability

- All runs use `numpy.random.default_rng(seed=42)`.
- `N_ITER = 500` gives stable mean estimates
  (Monte Carlo SE < 0.01 for most conditions).
- Increasing to `N_ITER = 2000` halves the SE without changing
  aggregate patterns.

---

### C.5 Extending the simulation

| Task                   | How                                                             |
|------------------------|-----------------------------------------------------------------|
| Add a new attack       | Append `Attack(...)` to `ATTACKS` dict in `simulation_core.py` |
| Add a new defense      | Append `Defense(...)` to `DEFENSES` dict                       |
| Add a new platform     | Append `Platform(...)` to `PLATFORMS` dict                     |
| Add a new chain        | Append tuple to `CHAINS` list                                   |
| Change attacker model  | Modify `ATTACKER_LEVELS` dict                                   |
| Run a grid subset      | Filter `run_full_grid()` output with pandas boolean indexing    |

---

### C.6 Code availability statement

Complete simulation code and result tables are available at:
https://github.com/TSQTT-CyberLab/secagentbench-simulation-repro

Prior to acceptance, code and data are available from the
corresponding author upon reasonable request.

---

## Appendix D. Illustrative Python Snippet

The following condensed snippet shows the core per-trial logic
inside `simulate_condition()`.
Full implementation: `code/simulation_core.py` (v3).

```python
import numpy as np

def simulate_single_trial(
    base_risk: float,
    layer_bonus: float,
    detect_prob: float,
    defense_mitigation: float,
    defense_fp_rate: float,
    workload_delta: float,
    base_latency: float,
    defense_overhead: float,
    rng: np.random.Generator,
) -> dict:
    """
    Single Monte Carlo trial for one (P, A, D, K, W) condition.

    Returns
    -------
    dict with keys: detected, success, fp, latency
    """
    # Step 1 - detection
    detected = bool(rng.random() < detect_prob)

    # Step 2 - mitigation (partial if undetected)
    mitig = defense_mitigation * (1.0 if detected else 0.45)

    # Step 3 - per-trial attack success
    noise   = float(rng.normal(0.0, 0.035))
    asr     = float(np.clip(
        base_risk + layer_bonus - mitig + noise, 0.01, 0.99
    ))
    success = bool(rng.random() < asr)

    # Step 4 - defense false positive on benign operation
    fp = bool(rng.random() < defense_fp_rate * (1.0 + workload_delta))

    # Step 5 - latency sample
    lat_noise = float(rng.normal(0.0, 0.02))
    latency   = base_latency * (
        1.0 + defense_overhead + workload_delta + lat_noise
    )

    return {
        "detected": detected,
        "success":  success,
        "fp":       fp,
        "latency":  latency,
    }
```

---

## Appendix E. Outcome Variable Definitions

| Symbol | Full name                   | Definition                                                                  |
|--------|-----------------------------|-----------------------------------------------------------------------------|
| ASR    | Attack Success Rate         | Proportion of trials where attacker achieves its objective                  |
| DDR    | Defense Detection Rate      | Proportion of trials where defense detects the attack                       |
| FPR-D  | False Positive Rate         | Proportion of benign operations incorrectly flagged by the defense          |
| PEP    | Privilege Escalation Prob.  | Probability lower-privilege compromise leads to high-privilege action       |
| ASupR  | Alert Suppression Rate      | Proportion of genuine alerts suppressed or downgraded by the attack         |
| DOI    | Defense Overhead Index      | Mean per-trial latency normalised to platform baseline (1.0 = no overhead)  |
| CLAF   | Cross-Layer Amplif. Factor  | Chained ASR / mean isolated ASR; values > 1.0 indicate amplification        |

---

## Appendix F. OWASP Agentic AI Top 10 Mapping

| Attack                | OWASP Risk Category                 | Risk ID |
|-----------------------|-------------------------------------|---------|
| A1: SIEM Injection    | Prompt Injection                    | ASI01   |
| A2: Alert Crafting    | Prompt Injection                    | ASI01   |
| A3: Context Poisoning | Memory and Context Manipulation     | ASI04   |
| A4: Tool Poisoning    | Tool and Plugin Misuse              | ASI02   |
| A5: Rug Pull          | Tool and Plugin Misuse              | ASI02   |
| A6: Response Spoofing | Tool and Plugin Misuse              | ASI02   |
| A7: Collusion         | Multi-Agent Trust and Coordination  | ASI06   |
| A8: Privilege Escal.  | Identity and Privilege Abuse        | ASI03   |
| A9: Goal Hijacking    | Goal and Objective Hijacking        | ASI01   |

---

## Appendix G. Changelog

| Version | Date       | Changes                                                                 |
|---------|------------|-------------------------------------------------------------------------|
| v1      | 2026-04    | Initial draft – Appendix A-C only                                       |
| v2      | 2026-04    | Added Appendix D (Python snippet)                                       |
| v3      | 2026-05-02 | Added Table 1 and Table 5 generators; added Appendix E (variable definitions), F (OWASP mapping), G (changelog); synced all parameters with simulation_core.py v3 |

---

*End of Appendix*
