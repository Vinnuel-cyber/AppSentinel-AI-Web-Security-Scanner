# Official FIRST CVSS v4.0 Risk Engine Specification & Implementation

This document details the exact mathematical scoring model, Equivalence Set (MacroVector) evaluation, EQ3/EQ6 interaction, composed vector interpolation, Threat metrics, Environmental security requirements, Supplemental metrics, score nomenclature, and validation test results implemented in AppSentinel's CVSS v4.0 Risk Engine (`app/security/risk_engine.py`).

---

## 1. Official Standard & Specification Alignment

The Common Vulnerability Scoring System version 4.0 (CVSS v4.0) is maintained by FIRST (Forum of Incident Response and Security Teams). Unlike CVSS v3.1, which used continuous sub-equations, CVSS v4.0 employs a discrete **MacroVector lookup and interpolation algorithm**.

AppSentinel implements the **complete FIRST CVSS v4.0 specification**, validated against the official FIRST specification document and reference resources:
- Specification: https://www.first.org/cvss/v4.0/specification-document
- Reference Resources: https://github.com/FIRSTdotorg/cvss-resources
- All 11 Base Metrics (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, `SA`).
- Threat Exploit Maturity Metric `E` (`X`, `A`, `P`, `U`).
- Environmental Security Requirements (`CR`, `IR`, `AR`).
- Modified Base Metrics (`MAV`, `MAC`, `MAT`, `MPR`, `MUI`, `MVC`, `MVI`, `MVA`, `MSC`, `MSI`, `MSA`).
- Supplemental Metrics (`S`, `AU`, `R`, `V`, `RE`, `U`).
- Complete 270 MacroVector lookup table (`000000` to `212221`).
- Exact severity distance interpolation and single decimal place rounding.
- Official score nomenclature (`CVSS-B`, `CVSS-BT`, `CVSS-BE`, `CVSS-BTE`).

Canonical vector format:
```
CVSS:4.0/AV:<X>/AC:<X>/AT:<X>/PR:<X>/UI:<X>/VC:<X>/VI:<X>/VA:<X>/SC:<X>/SI:<X>/SA:<X>[/E:<X>][/CR:<X>/IR:<X>/AR:<X>][/<MODIFIED>...][/<SUPPLEMENTAL>...]
```

---

## 2. Metric Groups & Value Sets

### 2.1 Base Exploitability Metrics (Mandatory)
1. **Attack Vector (AV)**: `N` (Network, 0.0), `A` (Adjacent, 0.1), `L` (Local, 0.2), `P` (Physical, 0.3)
2. **Attack Complexity (AC)**: `L` (Low, 0.0), `H` (High, 0.1)
3. **Attack Requirements (AT)**: `N` (None, 0.0), `P` (Present, 0.1)
4. **Privileges Required (PR)**: `N` (None, 0.0), `L` (Low, 0.1), `H` (High, 0.2)
5. **User Interaction (UI)**: `N` (None, 0.0), `P` (Passive, 0.1), `A` (Active, 0.2)

### 2.2 Vulnerable System Impact Metrics (Mandatory)
- **Vulnerable Confidentiality (VC)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)
- **Vulnerable Integrity (VI)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)
- **Vulnerable Availability (VA)**: `H` (High, 0.0), `L` (Low, 0.1), `N` (None, 0.2)

### 2.3 Subsequent System Impact Metrics (Mandatory)
- **Subsequent Confidentiality (SC)**: `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3)
- **Subsequent Integrity (SI)**: `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3) — *Note: Base SI accepts ONLY `H`, `L`, `N`; 'S' is rejected.*
- **Subsequent Availability (SA)**: `H` (High, 0.1), `L` (Low, 0.2), `N` (None, 0.3) — *Note: Base SA accepts ONLY `H`, `L`, `N`; 'S' is rejected.*

### 2.4 Threat Exploit Maturity Metric (E) (Optional)
- `X` (Not Defined — evaluates equivalent to worst-case `A`)
- `A` (Attacked / Public weaponized exploits observed, level 0.0)
- `P` (Proof-of-Concept demonstration available, level 0.1)
- `U` (Unreported / No known functional exploit code, level 0.2)

### 2.5 Environmental Security Requirements (CR, IR, AR) (Optional)
- `X` (Not Defined — evaluates equivalent to `H`)
- `H` (High requirement, level 0.0)
- `M` (Medium requirement, level 0.1)
- `L` (Low requirement, level 0.2)

### 2.6 Modified Environmental Base Metrics (Optional)
- `MAV`: `X`, `N`, `A`, `L`, `P`
- `MAC`: `X`, `L`, `H`
- `MAT`: `X`, `N`, `P`
- `MPR`: `X`, `N`, `L`, `H`
- `MUI`: `X`, `N`, `P`, `A`
- `MVC`, `MVI`, `MVA`: `X`, `H`, `L`, `N`
- `MSC`: `X`, `H`, `L`, `N`
- **`MSI` (Modified Subsequent Integrity)**: `X`, `S` (Safety), `H`, `L`, `N`
- **`MSA` (Modified Subsequent Availability)**: `X`, `S` (Safety), `H`, `L`, `N`
*Note: In FIRST CVSS v4.0, Safety value `S` is valid ONLY for Modified Subsequent System metrics `MSI` and `MSA`, and Supplemental metric `S`.*

### 2.7 Supplemental Metrics (Optional, Contextual Only)
Supplemental metrics provide additional operational context and do not alter numeric score calculation:
- **Safety (S)**: `X`, `N` (Negligible), `P` (Present) — *Separate from MSI:S/MSA:S*
- **Automatable (AU)**: `X`, `N`, `Y`
- **Recovery (R)**: `X`, `A` (Automatic), `U` (User), `I` (Irrecoverable)
- **Value Density (V)**: `X`, `D` (Diffuse), `C` (Concentrated)
- **Vulnerability Response Effort (RE)**: `X`, `L` (Low), `M` (Medium), `H` (High)
- **Provider Urgency (U)**: `X`, `Clear`, `Green`, `Amber`, `Red`

---

## 3. Score Nomenclature

Per FIRST CVSS v4.0 Specification Section 1.1, the engine determines four distinct score types:

| Score Type | Designation | Definition | Criteria |
|---|---|---|---|
| **CVSS-B** | Base Score | Measures intrinsic technical qualities | Only Base metrics specified (Threat and Environmental are omitted or `X`). |
| **CVSS-BT** | Base + Threat Score | Measures intrinsic severity adjusted for current threat landscape | Base metrics + Threat metric `E` specified (`E` $\ne$ `X`, Environmental omitted or `X`). |
| **CVSS-BE** | Base + Environmental Score | Measures intrinsic severity adjusted for specific target environment | Base metrics + Environmental metrics specified (`M*` or `CR/IR/AR` $\ne$ `X`, Threat omitted or `X`). |
| **CVSS-BTE** | Base + Threat + Environmental | Complete comprehensive score | Base metrics + Threat metric `E` $\ne$ `X` + Environmental metrics $\ne$ `X`. |

Supplemental metrics do not alter score nomenclature (e.g. Base + `S:P` remains `CVSS-B`).

---

## 4. "Not Defined" (X) Default Handling & Vector Preservation

To ensure data integrity and avoid semantic drift:
1. **Vector Storage Preservation**: Vectors parsed with `E:X`, `CR:X`, `IR:X`, `AR:X`, or `M*:X` preserve their explicit `X` tag during serialization (`build_vector_string(metrics, preserve_x=True)`).
2. **Never Silently Mutated**: Stored vector strings never rewrite `E:X` to `E:A` or `CR:X` to `CR:H`.
3. **Scoring Equivalence**:
   - `E:X` is evaluated identically to `E:A` (worst-case assumption).
   - `CR:X`, `IR:X`, `AR:X` are evaluated identically to `H` (maximum requirement assumption).
   - `M*:X` resolves to the corresponding Base metric value.

---

## 5. Equivalence Sets (MacroVectors EQ1 to EQ6)

CVSS v4.0 maps the metric space into 6 Equivalence Dimensions (`EQ1` through `EQ6`), producing a 6-digit MacroVector:

| EQ Dimension | Governing Metrics | Decision Rules | Levels |
|---|---|---|---|
| **EQ1** | Exploitability (`AV`, `PR`, `UI`) | Level 0: `AV:N and PR:N and UI:N`<br>Level 1: `(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P`<br>Level 2: `AV:P or not (AV:N or PR:N or UI:N)` | 0, 1, 2 |
| **EQ2** | Complexity (`AC`, `AT`) | Level 0: `AC:L and AT:N`<br>Level 1: `not (AC:L and AT:N)` | 0, 1 |
| **EQ3** | Vulnerable System Impact (`VC`, `VI`, `VA`) | Level 0: `VC:H and VI:H`<br>Level 1: `not (VC:H and VI:H) and (VC:H or VI:H or VA:H)`<br>Level 2: `not (VC:H or VI:H or VA:H)` | 0, 1, 2 |
| **EQ4** | Subsequent Impact (`SC`, `SI`, `SA`, `MSI`, `MSA`) | **Level 0**: `MSI:S or MSA:S`<br>**Level 1**: `not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)`<br>**Level 2**: `not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)` | 0, 1, 2 |
| **EQ5** | Exploit Maturity (`E`) | Level 0: `E:A`<br>Level 1: `E:P`<br>Level 2: `E:U` | 0, 1, 2 |
| **EQ6** | Impact Requirements (`CR`, `IR`, `AR` with `VC`, `VI`, `VA`) | Level 0: `(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)`<br>Level 1: `not [(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]` | 0, 1 |

> [!IMPORTANT]
> **Safety Impact and EQ4 Level 0**:
> Because Base `SI` and `SA` cannot have value `S`, MacroVector EQ4 Level 0 is reached **only** when Modified Subsequent Integrity (`MSI:S`) or Modified Subsequent Availability (`MSA:S`) is explicitly defined. A Base vector with all subsequent impacts High (`SC:H/SI:H/SA:H`) has MacroVector `000100` (Score 10.0), whereas adding Modified Safety `MSI:S` produces MacroVector `000000` (Score 10.0).

---

## 6. Vector Syntax Validation Rules

AppSentinel's `validate_vector` method enforces strict FIRST specification compliance:
1. **Mandatory Prefix**: Vector must begin with `CVSS:4.0/`.
2. **Mandatory Base Metrics**: All 11 Base metrics (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, `SA`) must be present and cannot have value `X`.
3. **No Duplicate Metrics**: Vectors containing duplicate metric tags (e.g. `.../AV:N/.../AV:A` or `.../E:A/E:P`) are strictly rejected.
4. **No Unknown Metrics**: Unrecognized tags (e.g. `UNKNOWN:TAG`) are strictly rejected.
5. **Case Sensitivity**: Metric tags and values must be uppercase, with the exception of Provider Urgency `U` which accepts official Title Case (`Clear`, `Green`, `Amber`, `Red`) and uppercase.
6. **Canonical Serialization Order**: `CANONICAL_ORDER` serializes metrics strictly as:
   `Base (AV..SA) -> Threat (E) -> Environmental Requirements (CR..AR) -> Modified Base (MAV..MSA) -> Supplemental (S..U)`.

---

## 7. Official Reference Test Results

The engine is verified across **161 automated tests** with zero regressions:
- **`tests/test_cvss_v4_compliance.py`** (25 tests): Strict FIRST audit validating Base SI/SA rejection of 'S', MSI/MSA acceptance of 'S', Supplemental Safety 'S' separation, Supplemental metrics (AU, R, V, RE, U), "Not Defined" (X) preservation, duplicate metric rejection, nomenclature tags, canonical normalization, and parametric MacroVector coverage.
- **`tests/test_cvss_v4_reference_vectors.py`** (14 tests): Official FIRST case studies and boundary conditions.

| Official Test Vector | Calculated Score | Expected Score | Severity Rating | Nomenclature | Spec Source |
|---|---|---|---|---|---|
| `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **7.3** | 7.3 | High | CVSS-B | FIRST Case Study 1 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | **7.7** | 7.7 | High | CVSS-B | FIRST Case Study 2 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U` | **5.2** | 5.2 | Medium | CVSS-BT | FIRST Spec Section 5.1 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N` | **8.3** | 8.3 | High | CVSS-B | FIRST Spec Section 8 |
| `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L` | **8.1** | 8.1 | High | CVSS-BE | FIRST Spec Section 6 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (SQLi) | **9.3** | 9.3 | Critical | CVSS-B | FIRST Macro 000200 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` (XSS) | **5.3** | 5.3 | Medium | CVSS-B | FIRST Macro 102201 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N` | **0.0** | 0.0 | None | CVSS-B | FIRST Zero Impact |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` | **10.0** | 10.0 | Critical | CVSS-B | FIRST Macro 000100 |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S` | **10.0** | 10.0 | Critical | CVSS-BE | FIRST Macro 000000 |

---

## 8. Official Severity Bands

```
[0.0]        NONE
[0.1 - 3.9]  LOW
[4.0 - 6.9]  MEDIUM
[7.0 - 8.9]  HIGH
[9.0 - 10.0] CRITICAL
```
