"""
AI Risk Explanation Service
Generates human-readable explanations of risk.
"""
from typing import Dict, Any
from .models import AIIntelligenceModel

def explain_risk(context: Dict[str, Any], model: AIIntelligenceModel = None) -> Dict[str, Any]:
    """
    Takes a Risk Context object and returns a human-readable explanation of the risk.
    """
    if model is None:
        model = AIIntelligenceModel()
    
    return model.generate_explanation(context)
