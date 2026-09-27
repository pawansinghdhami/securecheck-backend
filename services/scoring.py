def calculate_security_score(findings):

    risk_points = {
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "NONE": 0
    }

    total_risk = sum(
        risk_points.get(
            finding["severity"].upper(),
            0
        )
        for finding in findings
    )

    score = max(0, 100 - total_risk)

    return score
