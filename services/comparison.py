def compare_scans(db, scan_id):
    from models import Scan, Finding 
    # current scan
    current_scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
        )
    if current_scan is None:
        return {
            "error" : "Scan not found"
        }
    # previous scan for the same domain
    previous_scan = (
        db.query(Scan)
        .filter(Scan.domain == current_scan.domain,
                Scan.id < current_scan.id
            )
        .order_by(Scan.id.desc())
        .first()
        )
    # No previous scan available
    if previous_scan is None:
        return {
            "message" : "No previous scan is available for comparision",
            "current_scan" : {
            "id" : current_scan.id,
            "domain" : current_scan.domain,
            "security_score" : current_scan.security_score,
            "created_dtm" : current_scan.created_dtm
            }
        }
    # Get findings
    previous_findings = (
        db.query(Finding)
        .filter(Finding.scan_id == previous_scan.id)
        .all()
        )
    # current findings
    current_findings = (
        db.query(Finding)
        .filter(Finding.scan_id == current_scan.id)
        .all()
        )
    # previous by code
    previous_by_code = {
    finding.finding_code: finding
    for finding in previous_findings
    if finding.finding_code
    }
    # current by code
    current_by_code = {
        finding.finding_code: finding
        for finding in current_findings
        if finding.finding_code
    }

    previous_codes = set(previous_by_code.keys())
    current_codes = set(current_by_code.keys())

    fixed_codes = previous_codes - current_codes
    new_codes = current_codes - previous_codes
    still_present_codes = previous_codes & current_codes

    def finding_details(finding):
        return {
            "code": finding.finding_code,
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "evidence": finding.evidence
        }

    fixed_findings = [
        finding_details(previous_by_code[code])
        for code in fixed_codes
    ]

    new_findings = [
        finding_details(current_by_code[code])
        for code in new_codes
    ]

    still_present = [
        finding_details(current_by_code[code])
        for code in still_present_codes
    ]
    
    # Score comparision
    score_change = (
        current_scan.security_score - previous_scan.security_score
        )
    return {
        "domain" : current_scan.domain,
        "previous_scan" : { 
        "id" : previous_scan.id,
        "security_score" : previous_scan.security_score,
        "created_dtm" : previous_scan.created_dtm
        },
        "current_scan" : {
        "id": current_scan.id,
        "security_score": current_scan.security_score,
        "created_dtm": current_scan.created_dtm
        },
        "score_change": score_change,
        "findings_comparison" : {
        "fixed" : fixed_findings,
        "new" : new_findings,
        "still_present" : still_present
        }
    }