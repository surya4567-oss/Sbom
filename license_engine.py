"""
SBOM Risk Analyzer - License Compatibility Engine

This module implements a rule-based license compatibility evaluator.
It cross-references dependency licenses with an application's compliance policy,
handling complex cases such as dual-licensing, copyleft restrictions,
and unrecognized licenses.
"""

import logging
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("SBOMLicenseEngine")
logger.setLevel(logging.INFO)

# Setup logger handler if not present
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)


class LicenseEngineError(Exception):
    """Base exception for the license compatibility engine."""
    pass


class LicenseCompatibilityEngine:
    """
    Evaluates compliance and risk levels of dependency licenses
    against an application's policy guidelines.
    """

    def __init__(self, license_rules: List[Dict[str, Any]]):
        """
        Initializes the engine with rules from license_rules.json.

        Args:
            license_rules: A list of license rule dictionaries.
        """
        self.rules = {rule["license_name"].upper(): rule for rule in license_rules}
        logger.info(f"License compatibility engine initialized with {len(self.rules)} rules.")

    def _normalize_license(self, lic: str) -> str:
        """Helper to trim and upper-case license names for robust lookup."""
        return lic.strip().upper()

    def _parse_multi_license(self, license_str: str) -> Tuple[str, List[str]]:
        """
        Parses complex license strings (e.g. dual-licenses with 'OR' or multi-licenses with 'AND').
        Returns a tuple of (operator, list_of_licenses).
        """
        # Remove parentheses for simpler parsing
        cleaned = re.sub(r"[\(\)]", "", license_str)
        
        # Check OR first
        if " OR " in cleaned:
            parts = [p.strip() for p in cleaned.split(" OR ")]
            return "OR", parts
        if " / " in cleaned:
            parts = [p.strip() for p in cleaned.split(" / ")]
            return "OR", parts
        
        # Check AND
        if " AND " in cleaned:
            parts = [p.strip() for p in cleaned.split(" AND ")]
            return "AND", parts
        
        return "SINGLE", [license_str.strip()]

    def _evaluate_single(self, license_name: str, app_policy: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates a single license string against the application policy."""
        norm_name = self._normalize_license(license_name)
        is_proprietary = app_policy.get("is_proprietary", True)
        linking_type = app_policy.get("linking_type", "dynamic")
        distribution_type = app_policy.get("distribution_type", "saas")

        # Default rules lookup
        rule = self.rules.get(norm_name)

        # Retrieve risk level from rule or estimate
        risk_level = rule.get("risk_level", "Medium") if rule else "Medium"

        # 1. No license check
        if not license_name or norm_name in ("", "NONE", "NO LICENSE", "NULL", "UNDEFINED"):
            return {
                "license": license_name or "None",
                "status": "Unknown Legal Status",
                "risk_level": "Critical",
                "explanation": "No license declared. Default copyright laws apply, which prohibits reproduction or distribution without explicit permission."
            }

        # 2. Permissive license checks (MIT, Apache-2.0, BSD, ISC, Zlib, CC0)
        permissive_keywords = ["MIT", "APACHE", "BSD", "ISC", "ZLIB", "CC0", "PUBLIC DOMAIN"]
        is_permissive = any(k in norm_name for k in permissive_keywords)
        if is_permissive:
            return {
                "license": license_name,
                "status": "Compatible",
                "risk_level": "Low",
                "explanation": "Permissive license is fully compatible with proprietary and open-source applications."
            }

        # 3. Strong Copyleft checks (GPL, AGPL)
        copyleft_keywords = ["GPL", "AGPL"]
        # Make sure not to mismatch LGPL
        is_strong_copyleft = any(k in norm_name for k in copyleft_keywords) and "LGPL" not in norm_name
        if is_strong_copyleft:
            if is_proprietary:
                return {
                    "license": license_name,
                    "status": "Incompatible",
                    "risk_level": "High",
                    "explanation": f"Strong copyleft license ({license_name}) is incompatible with proprietary commercial applications."
                }
            else:
                return {
                    "license": license_name,
                    "status": "Needs Review",
                    "risk_level": "Medium",
                    "explanation": f"Strong copyleft license ({license_name}) used in an open-source project. Review required to ensure distribution alignment."
                }

        # 4. Weak Copyleft checks (LGPL)
        if "LGPL" in norm_name:
            if linking_type == "dynamic":
                return {
                    "license": license_name,
                    "status": "Compatible",
                    "risk_level": "Low",
                    "explanation": f"LGPL license ({license_name}) is compatible when dynamically linked."
                }
            else:
                return {
                    "license": license_name,
                    "status": "Low Risk Review",
                    "risk_level": "Medium",
                    "explanation": f"LGPL license ({license_name}) used in static linking or unspecified context. Low risk review is recommended."
                }

        # 5. Weak Copyleft checks (MPL, EPL, CDDL)
        weak_copyleft_keywords = ["MPL", "EPL", "CDDL"]
        is_weak_copyleft = any(k in norm_name for k in weak_copyleft_keywords)
        if is_weak_copyleft:
            if distribution_type == "redistributed":
                return {
                    "license": license_name,
                    "status": "Needs Review",
                    "risk_level": "Medium",
                    "explanation": f"Weak copyleft license ({license_name}) requires modifications to be open-sourced if redistributed."
                }
            else:
                return {
                    "license": license_name,
                    "status": "Compatible",
                    "risk_level": "Low",
                    "explanation": f"Weak copyleft license ({license_name}) is compatible for SaaS/internal use where modifications are not redistributed."
                }

        # 6. Proprietary license checks
        if "PROPRIETARY" in norm_name or "COMMERCIAL" in norm_name:
            allowed_proprietary = app_policy.get("allowed_proprietary_licenses", [])
            if license_name in allowed_proprietary:
                return {
                    "license": license_name,
                    "status": "Compatible",
                    "risk_level": "Low",
                    "explanation": "Proprietary license explicitly approved by company policy."
                }
            else:
                return {
                    "license": license_name,
                    "status": "Incompatible" if is_proprietary else "Needs Review",
                    "risk_level": "High",
                    "explanation": f"Proprietary license ({license_name}) is not approved. Compliance check required."
                }

        # 7. Fallback Unknown/Custom
        return {
            "license": license_name,
            "status": "Needs Review",
            "risk_level": risk_level,
            "explanation": f"Custom or unrecognized license ({license_name}). Manual legal review is required to determine compliance."
        }

    def evaluate_compatibility(self, license_name: str, app_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates the compatibility status, risk level, and explanation
        of a given license against the application policy.
        Handles dual-licensing (OR) and multi-licensing (AND) scenarios.

        Args:
            license_name: The name or expression of the license.
            app_policy: Application policy dict containing keys:
                        - is_proprietary: bool
                        - linking_type: "dynamic" | "static"
                        - distribution_type: "saas" | "redistributed"

        Returns:
            A dictionary containing:
            - license: str (original license input)
            - status: str ("Compatible", "Incompatible", "Needs Review", "Low Risk Review", "Unknown Legal Status")
            - risk_level: str ("Low", "Medium", "High", "Critical")
            - explanation: str
        """
        if not license_name:
            return self._evaluate_single(license_name, app_policy)

        operator, parts = self._parse_multi_license(license_name)

        if operator == "SINGLE" or len(parts) == 1:
            return self._evaluate_single(parts[0], app_policy)

        # Evaluate all parts
        evaluations = [self._evaluate_single(p, app_policy) for p in parts]

        # Compatibility precedence for choosing (high score is better/more compatible)
        # Compatible > Low Risk Review > Needs Review > Unknown Legal Status > Incompatible
        status_rank = {
            "Compatible": 5,
            "Low Risk Review": 4,
            "Needs Review": 3,
            "Unknown Legal Status": 2,
            "Incompatible": 1
        }
        
        risk_rank = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        if operator == "OR":
            # For OR dual-license, choose the best/most compatible license option
            best_eval = max(evaluations, key=lambda ev: status_rank.get(ev["status"], 0))
            return {
                "license": license_name,
                "status": best_eval["status"],
                "risk_level": best_eval["risk_level"],
                "explanation": (
                    f"Dual-licensed ({license_name}). Selected the more compatible option: "
                    f"'{best_eval['license']}' which is classified as {best_eval['status']}. "
                    f"Detail: {best_eval['explanation']}"
                )
            }
        else:
            # For AND multi-license, all licenses must be complied with, so select the worst/least compatible
            worst_eval = min(evaluations, key=lambda ev: status_rank.get(ev["status"], 0))
            
            # Risk level is the max risk among parts
            worst_risk = max(evaluations, key=lambda ev: risk_rank.get(ev["risk_level"], 0))["risk_level"]
            
            return {
                "license": license_name,
                "status": worst_eval["status"],
                "risk_level": worst_risk,
                "explanation": (
                    f"Multi-licensed with AND conjunction ({license_name}). All licenses must be complied with. "
                    f"Selected the limiting rule: '{worst_eval['license']}' which is classified as {worst_eval['status']}. "
                    f"Detail: {worst_eval['explanation']}"
                )
            }
