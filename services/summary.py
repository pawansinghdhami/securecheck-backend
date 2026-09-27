def build_summary(findings):
    summary = {
        "critical" : 0,
        "high"     : 0,
        "medium"   : 0,
        "low"      : 0 
    }        
    for finding in findings:
        severity = finding["severity"].lower()
        if severity in summary:
            summary[severity] += 1

    return summary