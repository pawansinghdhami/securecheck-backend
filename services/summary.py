def build_summary(findings):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for finding in findings:
        severity_value = finding.get("severity")

        if not isinstance(severity_value, str):
            continue

        severity = severity_value.lower()

        if severity in summary:
            summary[severity] += 1

    return summary