def calculate_risk(score):

    if score >= 80:
        return "Critical"

    elif score >= 50:
        return "High"

    elif score >= 20:
        return "Medium"

    return "Low"