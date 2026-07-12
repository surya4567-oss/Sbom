"""
SBOM Risk Analyzer - Report Generator
Generates the final modular report consumed by the frontend.
"""
from typing import Dict, Any, List

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ai.models import AIIntelligenceModel
from ai.context_builder import build_risk_context
from ai.explanation_service import explain_risk
from ai.remediation_service import generate_remediation_plan
from ai.executive_summary_service import generate_executive_summary
from ai.prioritization_service import prioritize_applications

from graph_analyzer import SBOMDependencyGraph
from risk_engine import WeightedRiskEngine


def generate_full_report(
    applications: List[Dict[str, Any]],
    sbom_graph: SBOMDependencyGraph,
    vulnerability_db: List[Dict[str, Any]],
    app_policy: Dict[str, Any],
    risk_engine: WeightedRiskEngine
) -> Dict[str, Any]:
    """
    Generates the complete modular report for all applications.
    """
    model = AIIntelligenceModel()
    
    all_contexts = []
    app_reports = []
    
    for app in applications:
        app_id = app["app_id"]
        try:
            # Phase 9: Risk Context Builder
            context = build_risk_context(app_id, sbom_graph, vulnerability_db, app_policy, risk_engine)
            all_contexts.append(context)
            
            # Phase 10: AI Risk Explanation
            explanation = explain_risk(context, model)
            
            # Phase 11: AI Remediation
            remediation = generate_remediation_plan(context, model)
            
            app_report = {
                "Application Information": {
                    "Name": context["Application Name"],
                    "Owner": context["Owner"],
                    "Business Criticality": context["Business Criticality"],
                    "Last Updated Date": context["Last Updated Date"]
                },
                "Risk Information": {
                    "Overall Risk Score": context["Overall Risk Score"],
                    "Risk Category": context["Risk Category"],
                    "Risk Breakdown": context["Risk Breakdown"]
                },
                "Dependency Details": {
                    "Total Dependencies": context["Total Dependencies"],
                    "Direct Dependencies": context["Direct Dependencies"],
                    "Transitive Dependencies": context["Transitive Dependencies"],
                    "Dependency Depth": context["Dependency Depth"],
                    "Dependency Paths": context["Dependency Paths"]
                },
                "Vulnerability Details": {
                    "Vulnerable Libraries": context["Vulnerable Libraries"],
                    "CVE IDs": context["CVE IDs"],
                    "CVSS Scores": context["CVSS Scores"],
                    "Patch Availability": context["Patch Availability"]
                },
                "License Findings": context["License Conflicts"],
                "Maintenance Findings": context["Maintenance Findings"],
                "AI Risk Explanation": explanation,
                "AI Remediation Plan": remediation
            }
            app_reports.append(app_report)
        except Exception as e:
            print(f"Error processing {app_id}: {e}")

    # Phase 12: Executive Summary
    exec_summary = generate_executive_summary(all_contexts, model)
    
    # Phase 13: Prioritization Engine
    priorities = prioritize_applications(all_contexts, model)
    
    final_report = {
        "Executive Summary": exec_summary,
        "Remediation Priority": priorities,
        "Applications": app_reports
    }
    
    return final_report
