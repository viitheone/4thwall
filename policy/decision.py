"""
Policy engine: combine ModSecurity result and ML score into final action.
EXACT logic only - no additional rules.
"""


def make_decision(modsecurity_blocked: bool, ml_score: float) -> dict:
    """
    EXACT logic:

    if modsecurity_blocked:
        return {'action': 'BLOCK', 'reason': 'ModSecurity rule triggered'}
    elif ml_score > 0.9:
        return {'action': 'BLOCK', 'reason': 'High ML risk score'}
    elif ml_score > 0.6:
        return {'action': 'ALERT', 'reason': 'Medium ML risk score'}
    else:
        return {'action': 'ALLOW', 'reason': 'Low risk'}

    Args:
        modsecurity_blocked: bool
        ml_score: float (0-1)

    Returns:
        dict with 'action' and 'reason'
    """
    if modsecurity_blocked:
        return {"action": "BLOCK", "reason": "ModSecurity rule triggered"}
    elif ml_score > 0.9:
        return {"action": "BLOCK", "reason": "High ML risk score"}
    elif ml_score > 0.6:
        return {"action": "ALERT", "reason": "Medium ML risk score"}
    else:
        return {"action": "ALLOW", "reason": "Low risk"}
