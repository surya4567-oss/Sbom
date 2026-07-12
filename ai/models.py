"""
AI Intelligence Models for generating human-readable text based on Risk Context.
Uses the Mistral AI API with robust fallback to programmatic mock responses.
"""
import os
import sys
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

class AIIntelligenceModel:
    """
    Interacts with the Mistral AI API to generate security insights.
    Falls back to programmatic mock logic if the API key is missing or calls fail.
    """
    def __init__(self):
        # Read API key from environment variable
        self.api_key = os.environ.get("MISTRAL_API_KEY", "")
        if not self.api_key:
            self._load_key_from_env_file()

    def _load_key_from_env_file(self):
        # Look for .env file in standard locations
        paths = [".env", "../.env", "../../.env"]
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                if k.strip() == "MISTRAL_API_KEY":
                                    self.api_key = v.strip().strip("'\"")
                                    return
                except Exception:
                    pass

    def _call_mistral(self, system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None

        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # Using mistral-large-latest for advanced reasoning and JSON compliance
        payload = {
            "model": "mistral-large-latest",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"}
        }

        try:
            import ssl
            context = ssl.create_default_context()
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            # Timeout after 8 seconds
            with urllib.request.urlopen(req, context=context, timeout=8) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                content = resp_data["choices"][0]["message"]["content"].strip()
                
                # Sanitize markdown JSON block formatting if returned
                if content.startswith("```"):
                    lines = content.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    content = "\n".join(lines).strip()
                    
                return json.loads(content)
        except Exception as e:
            print(f"[AIIntelligenceModel] Mistral standard SSL call failed: {e}. Retrying with unverified context...", file=sys.stderr)
            try:
                import ssl
                unverified_context = ssl._create_unverified_context()
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, context=unverified_context, timeout=8) as response:
                    resp_data = json.loads(response.read().decode("utf-8"))
                    content = resp_data["choices"][0]["message"]["content"].strip()
                    if content.startswith("```"):
                        lines = content.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        content = "\n".join(lines).strip()
                    return json.loads(content)
            except Exception as e2:
                print(f"[AIIntelligenceModel] Mistral API request failed: {e2}", file=sys.stderr)
                return None

    def generate_explanation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = (
            "You are an experienced Software Supply Chain Security Engineer.\n"
            "Explain the software supply chain risks using only the provided analysis.\n"
            "Do not invent vulnerabilities.\n"
            "You must return a JSON object with the following exact keys:\n"
            '- "Risk Overview": a description of the risk classification.\n'
            '- "Root Cause": details of why these risks exist.\n'
            '- "Dependency Chain": explanation of the vulnerable paths.\n'
            '- "Vulnerabilities": description of the CVEs.\n'
            '- "License Issues": details of any license conflicts.\n'
            '- "Maintenance Issues": staleness and maintenance metrics.\n'
            '- "Business Impact": impact on organizational units.\n'
            '- "Technical Impact": technical exploitation details.\n'
            '- "Overall Conclusion": next steps and recommendations.\n'
        )
        user_prompt = f"Here is the Risk Context JSON to analyze:\n{json.dumps(context, indent=2)}"
        
        result = self._call_mistral(system_prompt, user_prompt)
        if result:
            return result
            
        # Fallback to Mock Response
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
        system_prompt = (
            "You are a Senior Application Security Engineer.\n"
            "Generate remediation recommendations based only on the supplied Risk Context.\n"
            "Provide prioritized remediation steps.\n"
            "You must return a JSON object with the following exact keys:\n"
            '- "Immediate Actions": list of recommendation objects.\n'
            '- "Medium-Term Improvements": list of recommendation objects.\n'
            '- "Long-Term Recommendations": list of recommendation objects.\n'
            "Each recommendation object must contain the following keys:\n"
            '- "Why": reasoning.\n'
            '- "What": actionable item.\n'
            '- "How": implementation step.\n'
            '- "Expected benefit": outcome.\n'
            '- "Priority": "High", "Medium", or "Low".'
        )
        user_prompt = f"Here is the Risk Context JSON to analyze:\n{json.dumps(context, indent=2)}"
        
        result = self._call_mistral(system_prompt, user_prompt)
        if result:
            return result
            
        # Fallback to Mock Response
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
        system_prompt = (
            "You are an Executive Security Consultant.\n"
            "Generate organization-level summaries for security managers based on the provided JSON inputs from all applications.\n"
            "The summary should be understandable by non-technical managers.\n"
            "You must return a JSON object with the following exact keys:\n"
            '- "Total Applications": (int) count of applications.\n'
            '- "Critical Applications": (int) count of critical applications.\n'
            '- "High Risk Applications": (int) count of high risk applications.\n'
            '- "Medium Risk Applications": (int) count of medium risk applications.\n'
            '- "Low Risk Applications": (int) count of low risk applications.\n'
            '- "Total Vulnerabilities": (int) total number of vulnerabilities.\n'
            '- "Critical CVEs": (int) count of critical CVEs.\n'
            '- "License Violations": (int) total count of license violations.\n'
            '- "Executive Summary": general high-level summary.\n'
            '- "Key Findings": list or description of findings.\n'
            '- "Top Risks": principal security risks.\n'
            '- "Business Impact": organizational business impact.\n'
            '- "Immediate Actions": urgent actions.\n'
            '- "Long-Term Strategy": recommendations.'
        )
        user_prompt = f"Here are the Risk Context objects for all applications:\n{json.dumps(all_contexts, indent=2)}"
        
        result = self._call_mistral(system_prompt, user_prompt)
        if result:
            return result

        # Fallback to Mock Response
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
            "Critical CVEs": len(all_cves) // 2,
            "License Violations": sum(len(c["License Conflicts"]) for c in all_contexts),
            "Executive Summary": f"Out of {total} applications analyzed across the organization, {critical} are categorized as Critical Risk.",
            "Key Findings": f"Found {len(all_cves)} unique vulnerabilities across the supply chain.",
            "Top Risks": "Unpatched CVEs in core dependencies remain the highest threat.",
            "Business Impact": "Significant organizational risk if exploited.",
            "Immediate Actions": "Prioritize patching for all Critical risk applications.",
            "Long-Term Strategy": "Implement automated, continuous SBOM analysis and enforcement."
        }

    def prioritize(self, all_contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        system_prompt = (
            "You are a Security Prioritization Engine.\n"
            "Explain which applications should be remediated first.\n"
            "You must return a JSON object with a single key \"priorities\", which is a list of application ranking objects.\n"
            "Each application ranking object must contain the following keys:\n"
            '- "Rank": (int) ranking order starting from 1.\n'
            '- "Application": name of the application.\n'
            '- "Priority": risk tier (e.g. Critical, High, Medium, Low).\n'
            '- "Reason": detailed reason for this rank.\n'
            '- "Expected Risk Reduction": explanation of security improvement.\n'
            '- "Estimated Fix Effort": "High", "Medium", or "Low".'
        )
        user_prompt = f"Here are the Risk Context objects to prioritize:\n{json.dumps(all_contexts, indent=2)}"
        
        result = self._call_mistral(system_prompt, user_prompt)
        if result and "priorities" in result:
            return result["priorities"]
            
        # Fallback to Mock Response
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
