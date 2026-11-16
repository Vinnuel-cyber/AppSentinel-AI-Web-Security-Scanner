import re
from typing import Optional


class CVSS4RiskEngine:
    """Official FIRST CVSS v4.0 Specification Implementation.
    
    Implements the complete deterministic CVSS v4.0 scoring methodology developed by FIRST.
    Evaluates all 11 Base metrics, Threat metric E, Environmental requirements (CR, IR, AR),
    and Modified metrics (MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA).
    Calculates exact scores using MacroVectors (EQ1 - EQ6), composed highest vector distance,
    MSD interpolation, and standard round-to-tenth arithmetic.
    """

    CVSS_VERSION = "4.0"

    # Base Metrics
    REQUIRED_BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

    # Canonical Official CVSS v4.0 Metric Serialization Order (FIRST Specification Section 6)
    CANONICAL_ORDER = [
        # Base Metrics (Mandatory)
        "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
        # Threat Metric
        "E",
        # Environmental Security Requirements
        "CR", "IR", "AR",
        # Environmental Modified Base Metrics
        "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
        # Supplemental Metrics (Informational context)
        "S", "AU", "R", "V", "RE", "U",
    ]

    # Metric Value Levels for Severity Distances (FIRST specification)
    AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
    PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
    UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}

    AC_LEVELS = {"L": 0.0, "H": 0.1}
    AT_LEVELS = {"N": 0.0, "P": 0.1}

    VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
    VI_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
    VA_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}

    SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
    SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
    SA_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}

    CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
    IR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
    AR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}

    E_LEVELS  = {"U": 0.2, "P": 0.1, "A": 0.0}

    # Valid Metric Value Sets (FIRST CVSS v4.0 Official Specification)
    METRIC_VALUES = {
        # Base Metrics (Required, no 'X', Base SI/SA do NOT accept 'S')
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "AT": {"N", "P"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "P", "A"},
        "VC": {"H", "L", "N"},
        "VI": {"H", "L", "N"},
        "VA": {"H", "L", "N"},
        "SC": {"H", "L", "N"},
        "SI": {"H", "L", "N"},
        "SA": {"H", "L", "N"},
        # Threat Metric
        "E": {"X", "A", "P", "U"},
        # Environmental Security Requirements
        "CR": {"X", "H", "M", "L"},
        "IR": {"X", "H", "M", "L"},
        "AR": {"X", "H", "M", "L"},
        # Modified Base Metrics (MSI and MSA support the additional Safety value 'S')
        "MAV": {"X", "N", "A", "L", "P"},
        "MAC": {"X", "L", "H"},
        "MAT": {"X", "N", "P"},
        "MPR": {"X", "N", "L", "H"},
        "MUI": {"X", "N", "P", "A"},
        "MVC": {"X", "H", "L", "N"},
        "MVI": {"X", "H", "L", "N"},
        "MVA": {"X", "H", "L", "N"},
        "MSC": {"X", "H", "L", "N"},
        "MSI": {"X", "S", "H", "L", "N"},
        "MSA": {"X", "S", "H", "L", "N"},
        # Supplemental Metrics (Informational context, do not modify score)
        "S": {"X", "N", "P"},
        "AU": {"X", "N", "Y"},
        "R": {"X", "A", "U", "I"},
        "V": {"X", "D", "C"},
        "RE": {"X", "L", "M", "H"},
        "U": {"X", "Clear", "Green", "Amber", "Red", "CLEAR", "GREEN", "AMBER", "RED"},
    }

    # Max Severity Distances in EQs MacroVectors (FIRST Specification)
    MAX_SEVERITY_DEPTH = {
        "eq1": {0: 1, 1: 4, 2: 5},
        "eq2": {0: 1, 1: 2},
        "eq3eq6": {
            0: {0: 7, 1: 6},
            1: {0: 8, 1: 8},
            2: {1: 10},
        },
        "eq4": {0: 6, 1: 5, 2: 4},
        "eq5": {0: 1, 1: 1, 2: 1},
    }

    # Composed Highest Severity Vectors per Equivalence Set
    MAX_COMPOSED = {
        "eq1": {
            0: ["AV:N/PR:N/UI:N/"],
            1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        },
        "eq2": {
            0: ["AC:L/AT:N/"],
            1: ["AC:H/AT:N/", "AC:L/AT:P/"],
        },
        "eq3": {
            0: {
                "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
            },
            1: {
                "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                "1": [
                    "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                    "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                    "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                    "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                    "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
                ],
            },
            2: {
                "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
            },
        },
        "eq4": {
            0: ["SC:H/SI:S/SA:S/"],
            1: ["SC:H/SI:H/SA:H/"],
            2: ["SC:L/SI:L/SA:L/"],
        },
        "eq5": {
            0: ["E:A/"],
            1: ["E:P/"],
            2: ["E:U/"],
        },
    }

    # Complete Official 270 MacroVector Lookup Table (FIRST CVSS v4.0 Specification)
    MACRO_LOOKUP_TABLE = {
        "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
        "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
        "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
        "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
        "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
        "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
        "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5,
        "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
        "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9,
        "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
        "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
        "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
        "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4, "011201": 7, "011210": 7.1,
        "011211": 5.2, "011220": 5, "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2,
        "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
        "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
        "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
        "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
        "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
        "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
        "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
        "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
        "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9, "110010": 8.8,
        "110011": 7.6, "110020": 7.6, "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
        "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
        "110211": 5.9, "110220": 5.2, "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6,
        "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
        "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
        "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3,
        "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
        "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
        "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
        "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
        "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
        "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
        "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
        "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1,
        "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
        "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3, "210101": 5.5, "210110": 5.9,
        "210111": 4, "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
        "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
        "211011": 4.5, "211020": 4, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
        "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
        "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
        "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
    }

    # Reference Pre-Calibrated Base Profiles for Common Web Flaws
    VULN_BASE_PROFILES = {
        "sqli": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Unauthenticated remote SQL execution allowing complete database read/write/drop impact.",
        },
        "xss_reflected": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "P", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Reflected script execution in client browser with passive user interaction (clicking link).",
        },
        "cookie_no_httponly": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Session token accessible to client scripts, lowering barrier for session hijacking.",
        },
        "missing_security_header": {
            "metrics": {"AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "P", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Omission of defensive browser enforcement headers requiring specific secondary attack conditions.",
        },
        "server_banner_disclosure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Passive software version disclosure facilitating automated vulnerability reconnaissance.",
        },
        "sensitive_key_exposure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Accidental exposure of cryptographic private keys or cloud access tokens in public HTTP response.",
        },
        "directory_listing": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Public directory indexing allowing unrestricted enumeration of application files and directories.",
        },
        "stack_trace_disclosure": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Unhandled runtime exception leaking internal application source paths and execution state.",
        },
        "dangerous_http_methods": {
            "metrics": {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
            "explanation": "Web server advertises support for sensitive methods (PUT, DELETE, TRACE) on public routes.",
        },
    }

    @classmethod
    def resolve_metric(cls, sel: dict, metric: str) -> Optional[str]:
        """Resolve a metric value considering defaults and environmental overrides."""
        val = sel.get(metric)

        # Threat metric E: defaults to 'A' (Attacked / worst case) if 'X' or omitted
        if metric == "E" and (val is None or val == "X"):
            return "A"

        # Security Requirements CR, IR, AR: default to 'H' (High) if 'X' or omitted
        if metric in ("CR", "IR", "AR") and (val is None or val == "X"):
            return "H"

        # Modified environmental metrics overwrite base score values if defined and not 'X'
        mod_key = "M" + metric
        if mod_key in sel and sel[mod_key] and sel[mod_key] != "X":
            return sel[mod_key]

        # Direct Modified metric query (e.g. MAV, MSI): if 'X' or omitted, resolves to Base metric
        if metric.startswith("M") and metric[1:] in cls.REQUIRED_BASE_METRICS:
            if val is None or val == "X":
                return sel.get(metric[1:])

        return val

    @classmethod
    def extract_metric_from_str(cls, metric: str, text: str) -> Optional[str]:
        """Extract a single metric value from a composed vector segment string."""
        idx = text.find(metric + ":")
        if idx == -1:
            return None
        start = idx + len(metric) + 1
        end = text.find("/", start)
        return text[start:] if end == -1 else text[start:end]

    @classmethod
    def compute_macro_vector(cls, sel: dict) -> str:
        """Evaluate EQ1 through EQ6 equivalence sets per FIRST CVSS v4.0 specification."""
        m = cls.resolve_metric

        # EQ1: Exploitability (AV, PR, UI)
        av = m(sel, "AV")
        pr = m(sel, "PR")
        ui = m(sel, "UI")
        if av == "N" and pr == "N" and ui == "N":
            eq1 = 0
        elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P":
            eq1 = 1
        else:
            eq1 = 2

        # EQ2: Complexity (AC, AT)
        ac = m(sel, "AC")
        at = m(sel, "AT")
        eq2 = 0 if (ac == "L" and at == "N") else 1

        # EQ3: Vulnerable System Impact (VC, VI, VA)
        vc = m(sel, "VC")
        vi = m(sel, "VI")
        va = m(sel, "VA")
        if vc == "H" and vi == "H":
            eq3 = 0
        elif not (vc == "H" and vi == "H") and (vc == "H" or vi == "H" or va == "H"):
            eq3 = 1
        else:
            eq3 = 2

        # EQ4: Subsequent System Impact (SC, SI, SA, MSI, MSA)
        msi = m(sel, "MSI")
        msa = m(sel, "MSA")
        sc = m(sel, "SC")
        si = m(sel, "SI")
        sa = m(sel, "SA")
        if msi == "S" or msa == "S":
            eq4 = 0
        elif (sc == "H" or si == "H" or sa == "H"):
            eq4 = 1
        else:
            eq4 = 2

        # EQ5: Threat Exploit Maturity (E)
        e = m(sel, "E")
        if e == "A":
            eq5 = 0
        elif e == "P":
            eq5 = 1
        else:
            eq5 = 2

        # EQ6: Impact Requirements (CR, IR, AR with VC, VI, VA)
        cr = m(sel, "CR")
        ir = m(sel, "IR")
        ar = m(sel, "AR")
        if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
            eq6 = 0
        else:
            eq6 = 1

        return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

    @classmethod
    def validate_vector(cls, vector_str: str) -> tuple[bool, str, dict]:
        """Validate syntax of a CVSS v4.0 vector string."""
        if not vector_str or not isinstance(vector_str, str):
            return False, "Vector string is empty", {}

        clean_vec = vector_str.strip()
        if not clean_vec.startswith("CVSS:4.0/"):
            return False, "Vector must start with 'CVSS:4.0/' prefix", {}

        parts = clean_vec[9:].split("/")
        metrics = {}
        seen_metrics = set()
        for p in parts:
            if not p:
                continue
            if ":" not in p:
                return False, f"Invalid metric component: '{p}'", {}
            k, v = p.split(":", 1)
            k_clean = k.strip()
            v_clean = v.strip()

            # Reject duplicate metrics
            if k_clean in seen_metrics:
                return False, f"Duplicate metric '{k_clean}' in vector", {}
            seen_metrics.add(k_clean)

            # Metrics in CVSS v4.0 must be uppercase (except Provider Urgency U values which can be title/upper)
            if k_clean != k_clean.upper():
                return False, f"Metric tags and values must be uppercase: '{p}'", {}

            if k_clean != "U":
                if v_clean != v_clean.upper():
                    return False, f"Metric tags and values must be uppercase: '{p}'", {}
            else:
                if v_clean not in cls.METRIC_VALUES["U"]:
                    return False, f"Invalid value '{v_clean}' for metric 'U'", {}

            # Reject unrecognized metric keys
            if k_clean not in cls.METRIC_VALUES:
                return False, f"Unknown CVSS v4.0 metric '{k_clean}'", {}

            # Validate metric value against allowed set
            if v_clean not in cls.METRIC_VALUES[k_clean]:
                return False, f"Invalid value '{v_clean}' for metric '{k_clean}'", {}

            metrics[k_clean] = v_clean

        # Check required base metrics (all 11 must be present)
        for req in cls.REQUIRED_BASE_METRICS:
            if req not in metrics:
                return False, f"Missing required CVSS v4.0 metric '{req}'", {}
            val = metrics[req]
            if val not in cls.METRIC_VALUES[req]:
                return False, f"Invalid value '{val}' for metric '{req}'", {}

        return True, "Valid CVSS v4.0 vector", metrics

    @classmethod
    def calculate_score(cls, metrics: dict) -> float:
        """Calculate exact CVSS v4.0 score using FIRST MacroVectors and interpolation."""
        m = cls.resolve_metric

        # Zero impact shortcut: if all impact metrics are None, score is 0.0
        impact_metrics = ["VC", "VI", "VA", "SC", "SI", "SA"]
        if all(m(metrics, met) == "N" for met in impact_metrics):
            return 0.0

        mv = cls.compute_macro_vector(metrics)
        value = cls.MACRO_LOOKUP_TABLE.get(mv)
        if value is None:
            return 0.0

        eq1 = int(mv[0])
        eq2 = int(mv[1])
        eq3 = int(mv[2])
        eq4 = int(mv[3])
        eq5 = int(mv[4])
        eq6 = int(mv[5])

        # Compute next lower macrovectors for each dimension
        eq1_next = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
        eq2_next = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

        # EQ3 and EQ6 are coupled
        if eq3 == 1 and eq6 == 1:
            score_eq3eq6 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        elif eq3 == 0 and eq6 == 1:
            score_eq3eq6 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
        elif eq3 == 1 and eq6 == 0:
            score_eq3eq6 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        elif eq3 == 0 and eq6 == 0:
            left = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
            right = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
            if left is not None and right is not None:
                score_eq3eq6 = max(left, right)
            else:
                score_eq3eq6 = left if left is not None else right
        else:
            score_eq3eq6 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")

        score_eq1 = cls.MACRO_LOOKUP_TABLE.get(eq1_next)
        score_eq2 = cls.MACRO_LOOKUP_TABLE.get(eq2_next)
        score_eq4 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
        score_eq5 = cls.MACRO_LOOKUP_TABLE.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

        # Retrieve composed highest vectors for this macrovector
        eq1_maxes = cls.MAX_COMPOSED["eq1"][eq1]
        eq2_maxes = cls.MAX_COMPOSED["eq2"][eq2]
        eq3_eq6_maxes = cls.MAX_COMPOSED["eq3"][eq3][str(eq6)]
        eq4_maxes = cls.MAX_COMPOSED["eq4"][eq4]
        eq5_maxes = cls.MAX_COMPOSED["eq5"][eq5]

        max_vectors = [
            m1 + m2 + m36 + m4 + m5
            for m1 in eq1_maxes
            for m2 in eq2_maxes
            for m36 in eq3_eq6_maxes
            for m4 in eq4_maxes
            for m5 in eq5_maxes
        ]

        # Find matching max vector whose severity distances are all >= 0
        ext = cls.extract_metric_from_str
        chosen_distances = None

        for mv_cand in max_vectors:
            d_av = cls.AV_LEVELS[m(metrics, "AV")] - cls.AV_LEVELS[ext("AV", mv_cand)]
            d_pr = cls.PR_LEVELS[m(metrics, "PR")] - cls.PR_LEVELS[ext("PR", mv_cand)]
            d_ui = cls.UI_LEVELS[m(metrics, "UI")] - cls.UI_LEVELS[ext("UI", mv_cand)]
            d_ac = cls.AC_LEVELS[m(metrics, "AC")] - cls.AC_LEVELS[ext("AC", mv_cand)]
            d_at = cls.AT_LEVELS[m(metrics, "AT")] - cls.AT_LEVELS[ext("AT", mv_cand)]
            d_vc = cls.VC_LEVELS[m(metrics, "VC")] - cls.VC_LEVELS[ext("VC", mv_cand)]
            d_vi = cls.VI_LEVELS[m(metrics, "VI")] - cls.VI_LEVELS[ext("VI", mv_cand)]
            d_va = cls.VA_LEVELS[m(metrics, "VA")] - cls.VA_LEVELS[ext("VA", mv_cand)]
            d_sc = cls.SC_LEVELS[m(metrics, "SC")] - cls.SC_LEVELS[ext("SC", mv_cand)]
            d_si = cls.SI_LEVELS[m(metrics, "SI")] - cls.SI_LEVELS[ext("SI", mv_cand)]
            d_sa = cls.SA_LEVELS[m(metrics, "SA")] - cls.SA_LEVELS[ext("SA", mv_cand)]
            d_cr = cls.CR_LEVELS[m(metrics, "CR")] - cls.CR_LEVELS[ext("CR", mv_cand)]
            d_ir = cls.IR_LEVELS[m(metrics, "IR")] - cls.IR_LEVELS[ext("IR", mv_cand)]
            d_ar = cls.AR_LEVELS[m(metrics, "AR")] - cls.AR_LEVELS[ext("AR", mv_cand)]

            if any(d < 0 for d in [d_av, d_pr, d_ui, d_ac, d_at, d_vc, d_vi, d_va, d_sc, d_si, d_sa, d_cr, d_ir, d_ar]):
                continue
            chosen_distances = (d_av, d_pr, d_ui, d_ac, d_at, d_vc, d_vi, d_va, d_sc, d_si, d_sa, d_cr, d_ir, d_ar)
            break

        if not chosen_distances:
            return round(value, 1)

        d_av, d_pr, d_ui, d_ac, d_at, d_vc, d_vi, d_va, d_sc, d_si, d_sa, d_cr, d_ir, d_ar = chosen_distances
        cur_d_eq1 = d_av + d_pr + d_ui
        cur_d_eq2 = d_ac + d_at
        cur_d_eq3eq6 = d_vc + d_vi + d_va + d_cr + d_ir + d_ar
        cur_d_eq4 = d_sc + d_si + d_sa

        step = 0.1
        max_s_eq1 = cls.MAX_SEVERITY_DEPTH["eq1"][eq1] * step
        max_s_eq2 = cls.MAX_SEVERITY_DEPTH["eq2"][eq2] * step
        max_s_eq3eq6 = cls.MAX_SEVERITY_DEPTH["eq3eq6"][eq3][eq6] * step
        max_s_eq4 = cls.MAX_SEVERITY_DEPTH["eq4"][eq4] * step

        n_existing = 0
        norm_severities = []

        if score_eq1 is not None:
            n_existing += 1
            avail = value - score_eq1
            norm_severities.append(avail * (cur_d_eq1 / max_s_eq1))

        if score_eq2 is not None:
            n_existing += 1
            avail = value - score_eq2
            norm_severities.append(avail * (cur_d_eq2 / max_s_eq2))

        if score_eq3eq6 is not None:
            n_existing += 1
            avail = value - score_eq3eq6
            norm_severities.append(avail * (cur_d_eq3eq6 / max_s_eq3eq6))

        if score_eq4 is not None:
            n_existing += 1
            avail = value - score_eq4
            norm_severities.append(avail * (cur_d_eq4 / max_s_eq4))

        if score_eq5 is not None:
            n_existing += 1
            norm_severities.append(0.0)

        mean_dist = (sum(norm_severities) / n_existing) if n_existing > 0 else 0.0
        final_score = value - mean_dist
        final_score = max(0.0, min(10.0, final_score))
        return round(final_score, 1)

    @classmethod
    def get_severity_rating(cls, score: float) -> str:
        """Map numeric score to official CVSS v4.0 severity rating."""
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        else:
            return "Critical"

    @classmethod
    def get_score_nomenclature(cls, metrics: dict) -> str:
        """Determine CVSS v4.0 score nomenclature prefix (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE).
        
        Per FIRST CVSS v4.0 Specification Section 1.1:
        - CVSS-B: Base metrics only (Threat and Environmental are omitted or Not Defined X).
        - CVSS-BT: Base + Threat metrics specified (Threat != X and Environmental == X/omitted).
        - CVSS-BE: Base + Environmental metrics specified (Environmental != X and Threat == X/omitted).
        - CVSS-BTE: Base + Threat + Environmental metrics specified (both Threat != X and Environmental != X).
        Supplemental metrics do not alter score nomenclature.
        """
        has_threat = "E" in metrics and metrics["E"] not in (None, "X")

        env_keys = [
            "CR", "IR", "AR",
            "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
        ]
        has_env = any(k in metrics and metrics[k] not in (None, "X") for k in env_keys)

        if has_threat and has_env:
            return "CVSS-BTE"
        elif has_threat:
            return "CVSS-BT"
        elif has_env:
            return "CVSS-BE"
        else:
            return "CVSS-B"

    @classmethod
    def get_nomenclature(cls, metrics: dict) -> str:
        """Alias for get_score_nomenclature."""
        return cls.get_score_nomenclature(metrics)

    @classmethod
    def build_vector_string(cls, metrics: dict, preserve_x: bool = True) -> str:
        """Construct canonical CVSS:4.0 vector string in official specification order.
        
        Args:
            metrics: Dictionary of metric key-value pairs.
            preserve_x: If True (default), metrics explicitly set to 'X' in metrics
                        dict are retained in the output string. If False, 'X' metrics
                        are omitted.
        """
        parts = ["CVSS:4.0"]
        # Required base metrics first
        for k in cls.REQUIRED_BASE_METRICS:
            v = metrics.get(k, "N")
            parts.append(f"{k}:{v}")

        # Optional metrics in canonical order: Threat -> Environmental -> Supplemental
        for k in cls.CANONICAL_ORDER:
            if k in cls.REQUIRED_BASE_METRICS:
                continue
            if k in metrics:
                val = metrics[k]
                if val == "X" and not preserve_x:
                    continue
                parts.append(f"{k}:{val}")

        return "/".join(parts)

    @classmethod
    def normalize_vector(cls, vector_str: str, preserve_x: bool = True) -> tuple[bool, str, str]:
        """Validate and return canonically ordered CVSS:4.0 vector string."""
        ok, msg, metrics = cls.validate_vector(vector_str)
        if not ok:
            return False, msg, ""
        canonical_vec = cls.build_vector_string(metrics, preserve_x=preserve_x)
        return True, "Vector normalized successfully", canonical_vec

    @classmethod
    def score_vulnerability(
        cls,
        vulnerability_name: str,
        category: str = "",
        custom_metrics: Optional[dict] = None,
    ) -> dict:
        """Produce CVSS v4.0 vector, numeric score, severity, nomenclature, and factor explanations."""
        name_lower = vulnerability_name.lower()
        cat_lower = category.lower()

        # Select pre-calibrated baseline profile
        if custom_metrics:
            chosen_metrics = custom_metrics
            explanation = "Custom analyst-supplied CVSS v4.0 metric parameters."
        elif "sql" in name_lower or "sqli" in cat_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["sqli"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["sqli"]["explanation"]
        elif "cross-site scripting" in name_lower or "xss" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["xss_reflected"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["xss_reflected"]["explanation"]
        elif "cookie" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["cookie_no_httponly"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["cookie_no_httponly"]["explanation"]
        elif "defensive header" in name_lower or "missing" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["missing_security_header"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["missing_security_header"]["explanation"]
        elif "banner" in name_lower or "version" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["server_banner_disclosure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["server_banner_disclosure"]["explanation"]
        elif "sensitive" in name_lower or "private key" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["sensitive_key_exposure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["sensitive_key_exposure"]["explanation"]
        elif "directory" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["directory_listing"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["directory_listing"]["explanation"]
        elif "stack trace" in name_lower or "technical error" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["stack_trace_disclosure"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["stack_trace_disclosure"]["explanation"]
        elif "dangerous http" in name_lower or "methods" in name_lower:
            chosen_metrics = cls.VULN_BASE_PROFILES["dangerous_http_methods"]["metrics"]
            explanation = cls.VULN_BASE_PROFILES["dangerous_http_methods"]["explanation"]
        else:
            chosen_metrics = {
                "AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
                "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
            }
            explanation = "Conservative default web baseline metrics for general security misconfiguration."

        vector_str = cls.build_vector_string(chosen_metrics)
        score = cls.calculate_score(chosen_metrics)
        severity = cls.get_severity_rating(score)
        mv = cls.compute_macro_vector(chosen_metrics)
        nomenclature = cls.get_score_nomenclature(chosen_metrics)

        factors = {
            "attack_vector": chosen_metrics.get("AV"),
            "attack_complexity": chosen_metrics.get("AC"),
            "attack_requirements": chosen_metrics.get("AT"),
            "privileges_required": chosen_metrics.get("PR"),
            "user_interaction": chosen_metrics.get("UI"),
            "vulnerable_system_confidentiality": chosen_metrics.get("VC"),
            "vulnerable_system_integrity": chosen_metrics.get("VI"),
            "vulnerable_system_availability": chosen_metrics.get("VA"),
            "subsequent_system_impact": f"SC:{chosen_metrics.get('SC')} SI:{chosen_metrics.get('SI')} SA:{chosen_metrics.get('SA')}",
            "macro_vector": mv,
            "score_nomenclature": nomenclature,
            "rationale": explanation,
        }

        return {
            "cvss_version": cls.CVSS_VERSION,
            "cvss_vector": vector_str,
            "cvss_score": score,
            "severity_rating": severity,
            "score_nomenclature": nomenclature,
            "macro_vector": mv,
            "scoring_factors": factors,
        }
