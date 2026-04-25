
"""
Fraud Detection (ML-ready)

Currently this module uses a rule-based risk scoring system.
In future scope, you can replace `fraud_risk_score()` with a trained ML model
(Logistic Regression / RandomForest / XGBoost) using real historical data.
"""

def fraud_risk_score(name:str, email:str, route:str, pass_type:str, previous_applications:int=0):
    score = 0
    reasons = []

    # 1) Multiple applications from same email
    if previous_applications >= 1:
        score += 40
        reasons.append("Multiple applications from same email")

    # 2) Suspicious route text patterns
    if len(route) < 4:
        score += 15
        reasons.append("Route too short / unclear")
    if any(x in route.lower() for x in ["test", "dummy", "asdf", "xxxx"]):
        score += 20
        reasons.append("Route looks like dummy input")

    # 3) Pass type risk (example)
    if pass_type.lower() == "student":
        score += 10
        reasons.append("Student pass requires verification")

    # cap
    score = min(score, 100)

    if score >= 70:
        flag = "High"
    elif score >= 35:
        flag = "Medium"
    else:
        flag = "Low"

    reason_text = ", ".join(reasons) if reasons else "No risk patterns detected"
    return score, flag, reason_text
