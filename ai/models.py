"""
Mock AI Models for generating human-readable text based on Risk Context.
"""
from typing import Dict, Any, List

class AIIntelligenceModel:
    """
    Mocks an LLM to generate insights based on Risk Context.
    In a production system, this would interact with an API like OpenAI or Google Gemini.
    """
    def __init__(self):
        pass

    def generate_explanation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        app_name = context["Application Name"]
        risk_cat = context["Risk Category"]
        cves = context["CVE IDs"]
        
        return {
            "Risk Overview": f"The application {app_name} is classified as {risk_cat} risk.",
            "Root Cause": "Vulnerabilities found in dependencies.",
            "Dependency Chain": f"Vulnerable libraries identified: {', '.join(context['Vulnerable Libraries'][:3])}...",
            "Vulnerabilities": f"Found {len(cves)} CVEs: {', '.join(cves)}",
            "License Issues": f"Found {len(context['License Conflicts'])} license conflicts.",
            "Maintenance Issues": "Some dependencies might be stale based on lack of updates.",
            "Business Impact": f"High potential for exploit impacting {context['Business Criticality']} business unit workflows.",
            "Technical Impact": "Potential RCE or data exfiltration depending on the exact CVEs.",
            "Overall Conclusion": "Immediate remediation recommended to reduce attack surface."
        }

    def generate_remediation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Immediate Actions": [
                {
                    "Why": "Critical vulnerabilities present in supply chain.",
                    "What": "Upgrade vulnerable libraries.",
                    "How": "Use latest patched versions for identified vulnerable components.",
                    "Expected benefit": "Eliminates known exploits.",
                    "Priority": "High"
                }
            ],
            "Medium-Term Improvements": [
                {
                    "Why": "License conflicts violate internal policies.",
                    "What": "Review incompatible licenses.",
                    "How": "Replace libraries or get legal exception for the identified conflicts.",
                    "Expected benefit": "Reduces legal risk and compliance violations.",
                    "Priority": "Medium"
                }
            ],
            "Long-Term Recommendations": [
                {
                    "Why": "Need continuous security visibility.",
                    "What": "Integrate SBOM scanning in CI/CD pipeline.",
                    "How": "Add analysis steps to the automated build pipeline.",
                    "Expected benefit": "Prevents future regressions and ensures constant visibility.",
                    "Priority": "Low"
                }
            ]
        }

    def generate_summary(self, all_contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(all_contexts)
        critical = sum(1 for c in all_contexts if c["Risk Category"] == "Critical")
        high = sum(1 for c in all_contexts if c["Risk Category"] == "High")
        medium = sum(1 for c in all_contexts if c["Risk Category"] == "Medium")
        low = sum(1 for c in all_contexts if c["Risk Category"] in ("Moderate", "Low"))
        
        all_cves = set()
        for c in all_contexts:
            for cve in c["CVE IDs"]:
                all_cves.add(cve)
                
        return {
            "Total Applications": total,
            "Critical Applications": critical,
            "High Risk Applications": high,
            "Medium Risk Applications": medium,
            "Low Risk Applications": low,
            "Total Vulnerabilities": len(all_cves),
            "Critical CVEs": len(all_cves) // 2, # Mock estimation
            "License Violations": sum(len(c["License Conflicts"]) for c in all_contexts),
            "Executive Summary": f"Out of {total} applications analyzed across the organization, {critical} are categorized as Critical Risk.",
            "Key Findings": f"Found {len(all_cves)} unique vulnerabilities across the supply chain.",
            "Top Risks": "Unpatched CVEs in core dependencies remain the highest threat.",
            "Business Impact": "Significant organizational risk if exploited.",
            "Immediate Actions": "Prioritize patching for all Critical risk applications.",
            "Long-Term Strategy": "Implement automated, continuous SBOM analysis and enforcement."
        }

    def prioritize(self, all_contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Sort by Risk Score descending
        sorted_contexts = sorted(all_contexts, key=lambda x: x["Overall Risk Score"], reverse=True)
        priorities = []
        for i, ctx in enumerate(sorted_contexts):
            priorities.append({
                "Rank": i + 1,
                "Application": ctx["Application Name"],
                "Priority": ctx["Risk Category"],
                "Reason": f"Ranked #{i+1} due to a risk score of {ctx['Overall Risk Score']:.2f}, {len(ctx['CVE IDs'])} vulnerabilities, and {ctx['Business Criticality']} business criticality.",
                "Expected Risk Reduction": "High" if ctx['Overall Risk Score'] > 80 else "Medium",
                "Estimated Fix Effort": "High" if len(ctx["License Conflicts"]) > 0 else "Medium"
            })
        return priorities
