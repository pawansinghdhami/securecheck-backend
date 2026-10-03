from fastapi import FastAPI
from database import SessionLocal
from models import Scan, Finding
from scanners.https import check_https
from scanners.headers import check_security_headers
from services.findings import build_findings
from services.scoring import calculate_security_score
from services.summary import build_summary
from services.comparison import compare_scans
from scanners.cookies import check_cookie_security
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SecureCheck API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {
        "status" : "ok",
        "service" : "SecureCheck"
    }

@app.get("/check/https")
def https_check_endpoint(domain: str):
    return check_https(domain)

@app.get("/check/headers")
def security_headers_endpoint(domain: str):
    return check_security_headers(domain)
   
@app.post("/scan")
def run_scan(domain:str):
    https_result = check_https(domain)
    headers_result = check_security_headers(domain)
    cookies_result = check_cookie_security(domain)

    findings = build_findings(
        https_result,
        headers_result,
        cookies_result
    )

    security_score = calculate_security_score(findings)
    summary = build_summary(findings)

    #Database connection
    db = SessionLocal()

    try:
        scan = Scan(
            domain=domain,
            status="COMPLETED",
            security_score=security_score
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
    finally:
            db.close()

    #save findings 
    for finding_data in findings:
        finding = Finding(
            scan_id = scan.id,
            finding_code=finding_data["code"],
            title = finding_data["title"],
            severity = finding_data["severity"],
            status = finding_data["status"],
            description = finding_data["description"],
            recommendation = finding_data["recommendation"],
            evidence=finding_data.get("evidence")
        )        
        db.add(finding)
    db.commit()

    return {
        "id": scan.id,
        "domain" : domain,
        "status" : "COMPLETED",
        "security_score" : security_score,
        "summary" : summary,
        "findings" : findings
    }

@app.get("/scans/{domain}")
def get_scan_history(domain: str):
    db = SessionLocal()

    try:
        scans = (
            db.query(Scan)
            .filter(Scan.domain==domain)
            .order_by(Scan.created_dtm.desc())
            .all()
        )
        return [
            {
                "id" : scan.id,
                "domain" : scan.domain,
                "status" : scan.status,
                "security_score" : scan.security_score,
                "created_dtm" : scan.created_dtm
            }
            for scan in scans
        ]
    finally:
        db.close()

@app.get("/scans/id/{scan_id}")
def get_scan_details(scan_id: int):
    db = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )
        if scan is None:
            return {
                "error" : "Scan not found"
            }
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .all()
        )
        return {
            "id" : scan.id,
            "domain" : scan.domain,
            "status" : scan.status,
            "security_score" : scan.security_score,
            "created_dtm" : scan.created_dtm,
            "findings" : [
                {
                    "id" : finding.id,
                    "code": finding.finding_code,
                    "title" : finding.title,
                    "severity" : finding.severity,
                    "status" : finding.status,
                    "description" : finding.description,
                    "recommendation" : finding.recommendation,
                    "evidence": finding.evidence
                }
                for finding in findings
            ]
        }
    finally:
        db.close()

@app.get("/scans/id/{scan_id}/compare")
def compare_scan(scan_id: int):
    db = SessionLocal()
    try:
       return compare_scans(db, scan_id)
    finally:
        db.close()

@app.get("/check/cookies")
def cookie_security_endpoint(domain: str):
    return check_cookie_security(domain)

@app.get("/dashboard")
def get_dashboard():
    db = SessionLocal()

    try:
        # Total scans
        total_scans = db.query(Scan).count()

        # Latest scan
        latest_scan = (
            db.query(Scan)
            .order_by(Scan.created_dtm.desc(), Scan.id.desc())
            .first()
        )

        # Last 10 scans
        scans = (
            db.query(Scan)
            .order_by(Scan.created_dtm.desc(), Scan.id.desc())
            .limit(10)
            .all()
        )

        # Scan history
        scan_history = [
            {
                "id": scan.id,
                "domain": scan.domain,
                "security_score": scan.security_score,
                "status": scan.status,
                "created_dtm": scan.created_dtm
            }
            for scan in scans
        ]

        # Score trend
        score_trend = [
            {
                "id": scan.id,
                "domain": scan.domain,
                "score": scan.security_score,
                "created_dtm": scan.created_dtm
            }
            for scan in reversed(scans)
        ]

        # Latest scan summary
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        if latest_scan:
            latest_findings = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .all()
            )

            for finding in latest_findings:
                severity = finding.severity.lower()

                if severity in summary:
                    summary[severity] += 1

        # Latest scan data
        latest_scan_data = None

        if latest_scan:
            latest_scan_data = {
                "id": latest_scan.id,
                "domain": latest_scan.domain,
                "security_score": latest_scan.security_score,
                "status": latest_scan.status,
                "created_dtm": latest_scan.created_dtm
            }

        # Domain statistics
        all_scans = (
            db.query(Scan)
            .order_by(Scan.created_dtm.desc(), Scan.id.desc())
            .all()
        )

        domain_data = {}

        for scan in all_scans:
            if scan.domain not in domain_data:
                domain_data[scan.domain] = {
                    "domain": scan.domain,
                    "latest_score": scan.security_score,
                    "scan_count": 0
                }

            domain_data[scan.domain]["scan_count"] += 1

        domains = list(domain_data.values())

        return {
            "total_scans": total_scans,
            "latest_scan": latest_scan_data,
            "summary": summary,
            "scan_history": scan_history,
            "score_trend": score_trend,
            "domains": domains
        }

    finally:
        db.close()