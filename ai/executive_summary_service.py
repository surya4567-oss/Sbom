"""
AI Executive Summary Service
Generates organization-level summaries for security managers.
"""
from typing import Dict, Any, List
from .models import AIIntelligenceModel

def generate_executive_summary(all_contexts: List[Dict[str, Any]], model: AIIntelligenceModel = None) -> Dict[str, Any]:
    """
    Takes a list of all Risk Context objects and returns an executive summary.
    """
    if model is None:
        model = AIIntelligenceModel()
    
    return model.generate_summary(all_contexts)
