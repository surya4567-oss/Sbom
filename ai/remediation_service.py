"""
AI Remediation Generator Service
Generates actionable remediation plans.
"""
from typing import Dict, Any
from .models import AIIntelligenceModel

def generate_remediation_plan(context: Dict[str, Any], model: AIIntelligenceModel = None) -> Dict[str, Any]:
    """
    Takes a Risk Context object and returns actionable remediation steps.
    """
    if model is None:
        model = AIIntelligenceModel()
    
    return model.generate_remediation(context)
