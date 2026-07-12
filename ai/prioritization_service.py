"""
AI Prioritization Engine
Ranks applications for remediation based on various risk factors.
"""
from typing import Dict, Any, List
from .models import AIIntelligenceModel

def prioritize_applications(all_contexts: List[Dict[str, Any]], model: AIIntelligenceModel = None) -> List[Dict[str, Any]]:
    """
    Takes a list of Risk Context objects and returns a prioritized ranking list.
    """
    if model is None:
        model = AIIntelligenceModel()
    
    return model.prioritize(all_contexts)
