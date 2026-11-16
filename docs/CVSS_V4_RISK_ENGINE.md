# Official FIRST CVSS v4.0 Risk Engine Specification & Implementation

This document details the exact mathematical scoring model, Equivalence Set (MacroVector) evaluation, EQ3/EQ6 interaction, composed vector interpolation, Threat metrics, Environmental security requirements, and reference test results implemented in AppSentinel's CVSS v4.0 Risk Engine (`app/security/risk_engine.py`).

---

## 1. Official Standard & Specification Alignment

The Common Vulnerability Scoring System version 4.0 (CVSS v4.0) is maintained by FIRST (Forum of Incident Response and Security Teams). Unlike CVSS v3.1, which used continuous sub-equations, CVSS v4.0 employs a discrete **MacroVector lookup and interpolation algorithm**.

AppSentinel implements the **complete FIRST CVSS v4.0 specification**, validated against the official reference calculator:
- All 11 Base Metrics (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, `SA`).
- Threat Exploit Maturity Metric `E` (`X`, `A`, `P`, `U`).
- Environmental Security Requirements (`CR`, `IR`, `AR`).
- Modified Base Metrics (`MAV`, `MAC`, `MAT`, `MPR`, `MUI`, `MVC`, `MVI`, `MVA`, `MSC`, `MSI`, `MSA`).
- Complete 270 MacroVector lookup table (`000000` to `212221`).
- Exact severity distance interpolation and standard single decimal place rounding.

Canonical vector format:
```
CVSS:4.0/AV:<X>/AC:<X>/AT:<X>/PR:<X>/UI:<X>/VC:<X>/VI:<X>/VA:<X>/SC:<X>/SI:<X>/SA:<X>[/E:<X>][/CR:<X>/IR:<X>/AR:<X>][/<MODIFIED>...]
```

---

## 2. Metric Groups & Explanations

### 2.1 Base Exploitability Metrics
1. **Attack Vector (AV)**: `N` (Network, 0.0), `A` (Adjacent, 0.1), `L` (Local, 0.2), `P` (Physical, 0.3)
2. **Attack Complexity (AC)**: `L` (Low, 0.0), `H` (High, 0.1)
3. **Attack Requirements (AT)**: `N` (None, 0.0), `P` (Present, 0.1)
4. **Privileges Required (PR)**: `N` (None, 0.0), `L` (Low, 0.1), `H` (High, 0.2)
5. **User Interaction (UI)**: `N` (None, 0.0), `P` (Passive, 0.1), `A` (Active, 0.2)

### 2.2 Vulnerable System Impact Metrics
- **Vulnerable Confidentiality (VC)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)
- **Vulnerable Integrity (VI)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)
- **Vulnerable Availability (VA)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)

### 2.3 Subsequent System Impact Metrics
- **Subsequent Confidentiality (SC)**: `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3)
- **Subsequent Integrity (SI)**: `S` (Safety, 0.0), `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3)
- **Subsequent Availability (SA)**: `S` (Safety, 0.0), `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3)

### 2.4 Threat Exploit Maturity Metric (E)
- `X` (Not Defined - defaults to worst-case `A`)
- `A` (Attacked / Public weaponized exploits observed, level 0.0)
- `P` (Proof-of-Concept demonstration available, level 0.1)
- `U` (Unreported / No known functional exploit code, level 0.2)

### 2.5 Environmental Security Requirements (CR, IR, AR)
- `X` (Not Defined - defaults to `H`)
- `H` (High requirement, level 0.0)
- `M` (Medium requirement, level 0.1)
- `L` (Low requirement, level 0.2)

---

## 3. Equivalence Sets (MacroVectors EQ1 to EQ6)

CVSS v4.0 maps the metric space into 6 Equivalence Dimensions (`EQ1` through `EQ6`), producing a 6-digit MacroVector:

| EQ Dimension | Governing Metrics | Decision Rules | Levels |
|---|---|---|---|
| **EQ1** | Exploitability (`AV`, `PR`, `UI`) | Level 0: `AV:N and PR:N and UI:N`<br>Level 1: `(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P`<br>Level 2: `AV:P or not (AV:N or PR:N or UI:N)` | 0, 1, 2 |
| **EQ2** | Complexity (`AC`, `AT`) | Level 0: `AC:L and AT:N`<br>Level 1: `not (AC:L and AT:N)` | 0, 1 |
| **EQ3** | Vulnerable System Impact (`VC`, `VI`, `VA`) | Level 0: `VC:H and VI:H`<br>Level 1: `not (VC:H and VI:H) and (VC:H or VI:H or VA:H)`<br>Level 2: `not (VC:H or VI:H or VA:H)` | 0, 1, 2 |
| **EQ4** | Subsequent Impact (`SC`, `SI`, `SA`, `MSI`, `MSA`) | Level 0: `MSI:S or MSA:S`<br>Level 1: `not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)`<br>Level 2: `not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)` | 0, 1, 2 |
| **EQ5** | Exploit Maturity (`E`) | Level 0: `E:A`<br>Level 1: `E:P`<br>Level 2: `E:U` | 0, 1, 2 |
| **EQ6** | Impact Requirements (`CR`, `IR`, `AR` with `VC`, `VI`, `VA`) | Level 0: `(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)`<br>Level 1: `not [(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]` | 0, 1 |

---

## 4. EQ3 and EQ6 Coupling & Interpolation Algorithm

### 4.1 EQ3 and EQ6 Interaction
In the FIRST specification, EQ3 (Vulnerable Impact) and EQ6 (Environmental Impact Requirements) are inter-dependent when transitioning to lower MacroVectors:
- If `EQ3 == 1` and `EQ6 == 1` $\rightarrow$ Next lower is `EQ3 = 2, EQ6 = 1`
- If `EQ3 == 0` and `EQ6 == 1` $\rightarrow$ Next lower is `EQ3 = 1, EQ6 = 1`
- If `EQ3 == 1` and `EQ6 == 0` $\rightarrow$ Next lower is `EQ3 = 1, EQ6 = 1`
- If `EQ3 == 0` and `EQ6 == 0` $\rightarrow$ Two potential branches exist: `left` (`EQ3=0, EQ6=1`) and `right` (`EQ3=1, EQ6=0`). The algorithm selects whichever branch has the higher lookup score.

### 4.2 Severity Distance Calculation
The algorithm compares the target vector against pre-defined composed highest vectors (`MAX_COMPOSED`):
$$\text{distance} = \text{level}(\text{actual}) - \text{level}(\text{highest})$$
The first composed vector where all metric distances $\ge 0$ is selected.

### 4.3 Maximal Scoring Difference (MSD) Interpolation
For each dimension ($EQ_i$) where a lower MacroVector exists:
$$\text{available\_distance} = \text{value}_{\text{current}} - \text{score}_{\text{lower}}$$
$$\text{percent\_distance} = \frac{\text{current\_severity\_distance}}{\text{max\_depth} \times 0.1}$$
$$\text{normalized\_severity} = \text{available\_distance} \times \text{percent\_distance}$$

The mean of all existing normalized severities is subtracted from the current MacroVector score:
$$\text{Final Score} = \text{round}\left(\max\left(0.0, \min\left(10.0, \text{value} - \frac{\sum \text{normalized\_severities}}{N_{\text{existing}}}\right)\right), 1\right)$$

### 4.4 Special Shortcuts
- **Zero Impact Shortcut**: If all impact metrics (`VC`, `VI`, `VA`, `SC`, `SI`, `SA`) equal `N`, the score is immediately evaluated as **0.0 None** without interpolation.

---

## 5. Official Reference Test Results

AppSentinel's implementation is verified in `tests/test_cvss_v4_reference_vectors.py` against official FIRST test vectors:

| Official Test Vector | Calculated Score | Expected Score | Severity Rating | Spec Source |
|---|---|---|---|---|
| `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **7.3** | 7.3 | High | FIRST Case Study 1 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **7.7** | 7.7 | High | FIRST Case Study 2 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U` | **5.2** | 5.2 | Medium | FIRST Spec Section 5.1 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N` | **8.3** | 8.3 | High | FIRST Spec Section 8 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L` | **8.1** | 8.1 | High | FIRST Spec Section 6 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (SQLi) | **9.3** | 9.3 | Critical | FIRST Macro 000200 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` (XSS) | **5.3** | 5.3 | Medium | FIRST Macro 102201 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N` | **0.0** | 0.0 | None | FIRST Zero Impact |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` | **10.0** | 10.0 | Critical | FIRST Macro 000000 |

---

## 6. Official Severity Bands

```
[0.0]        NONE
[0.1 - 3.9]  LOW
[4.0 - 6.9]  MEDIUM
[7.0 - 8.9]  HIGH
[9.0 - 10.0] CRITICAL
```

---

## 7. Known Limitations

- **Supplemental Metrics**: FIRST defines optional Supplemental metrics (`Safety`, `Automatable`, `Recovery`, `Value Density`, `Vulnerability Response Effort`, `Provider Urgency`). These metrics are descriptive and do not affect the numeric score calculation.
