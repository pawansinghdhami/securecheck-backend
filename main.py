import ipaddress
import hashlib
import os
import re
import secrets
from fastapi import Cookie, Depends, FastAPI, Query, HTTPException, Response
from datetime import datetime, timedelta
from pydantic import BaseModel
from database import SessionLocal
from models import AuthSession, Scan, Finding, User
from services.passwords import hash_password, verify_password
from scanners.https import check_https
from scanners.headers import check_security_headers
from services.findings import build_findings
from services.scoring import calculate_security_score
from services.summary import build_summary
from services.comparison import compare_scans
from scanners.cookies import check_cookie_security
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from scanners.reachability import check_domain_reachability
from services.scan_deduplication import generate_scan_fingerprint
from sqlalchemy import String, Integer, DateTime, ForeignKey, func
from sqlalchemy.exc import IntegrityError

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

class SignupPayload(BaseModel):
    full_name: str
    email: str
    password: str

class LoginPayload(BaseModel):
    email: str
    password: str
    remember_me: bool = False

def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    if not domain:
        raise ValueError("Domain is required")

    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    parsed = urlparse(domain)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid domain")

    hostname = hostname.rstrip(".")

    if hostname in {"localhost"} or hostname.endswith(".localhost"):
        raise ValueError("Localhost and local development domains are not allowed")

    if hostname.endswith(".local") or hostname.endswith(".internal"):
        raise ValueError("Private or internal domains are not allowed")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None and (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    ):
        raise ValueError("Private, loopback, or reserved IP addresses are not allowed")

    return hostname

@app.get("/health")
def health_check():
    return {
        "status" : "ok",
        "service" : "SecureCheck"
    }

@app.post("/auth/signup", status_code=201)
def signup(payload: SignupPayload):
    full_name = payload.full_name.strip()
    email = payload.email.strip().lower()

    if not full_name or len(full_name) > 120:
        raise HTTPException(status_code=422, detail="Enter a name up to 120 characters.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    if len(payload.password) < 8 or len(payload.password) > 128:
        raise HTTPException(status_code=422, detail="Password must be 8 to 128 characters long.")

    db = SessionLocal()
    try:
        if db.query(User.id).filter(User.email == email).first():
            raise HTTPException(status_code=409, detail="An account with this email already exists.")

        user = User(
            full_name=full_name,
            email=email,
            password_hash=hash_password(payload.password),
        )
        db.add(user)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail="An account with this email already exists.")

        db.refresh(user)
        return {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "created_dtm": user.created_dtm,
        }
    finally:
        db.close()

@app.post("/auth/login")
def login(payload: LoginPayload, response: Response):
    email = payload.email.strip().lower()
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        session_token = secrets.token_urlsafe(32)
        lifetime = timedelta(days=30) if payload.remember_me else timedelta(hours=12)
        db.add(AuthSession(
            user_id=user.id,
            token_hash=hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
            expires_dtm=datetime.now() + lifetime,
        ))
        db.commit()

        response.set_cookie(
            key="vigilez_session",
            value=session_token,
            max_age=int(lifetime.total_seconds()) if payload.remember_me else None,
            httponly=True,
            secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
            samesite="lax",
            path="/",
        )
        return {"id": user.id, "full_name": user.full_name, "email": user.email}
    finally:
        db.close()

def require_current_user(vigilez_session: str | None = Cookie(default=None)) -> User:
    if not vigilez_session:
        raise HTTPException(status_code=401, detail="Authentication required.")

    token_hash = hashlib.sha256(vigilez_session.encode("utf-8")).hexdigest()
    db = SessionLocal()
    try:
        auth_session = (
            db.query(AuthSession)
            .filter(AuthSession.token_hash == token_hash)
            .first()
        )
        if not auth_session or auth_session.expires_dtm <= datetime.now():
            raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

        user = db.query(User).filter(User.id == auth_session.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return user
    finally:
        db.close()

@app.get("/check/https")
def https_check_endpoint(domain: str):
    return check_https(domain)

@app.get("/check/headers")
def security_headers_endpoint(domain: str):
    return check_security_headers(domain)
   
@app.post("/scan")
def run_scan(domain: str):
    try:
        domain = normalize_domain(domain)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    reachability_result = check_domain_reachability(domain)

    if not reachability_result["reachable"]:
        return {
            "domain": domain,
            "status": "FAILED",
            "security_score": None,
            "stage": reachability_result["stage"],
            "ip_address": reachability_result["ip_address"],
            "status_code": reachability_result["status_code"],
            "final_url": reachability_result["final_url"],
            "error": reachability_result["error"]
        }

    # Run scanners
    https_result = check_https(domain)
    headers_result = check_security_headers(domain)
    cookies_result = check_cookie_security(domain)

    canonical_domain = domain

    final_url = https_result.get("evidence", {}).get("final_url")

    if final_url:
        parsed_final_url = urlparse(final_url)
        
        if parsed_final_url.hostname:
            canonical_domain = parsed_final_url.hostname.lower().rstrip(".")

    print(
    f"requested={domain}, "
    f"final_url={final_url}, "
    f"canonical={canonical_domain}"
    )   

    # Generate fingerprint
    result_fingerprint = generate_scan_fingerprint(
        https_result,
        headers_result,
        cookies_result
    )

    # Check latest scan for this domain
    db = SessionLocal()

    try:
        latest_scan = (
            db.query(Scan)
            .filter(Scan.canonical_domain == canonical_domain)
            .order_by(
                Scan.created_dtm.desc(),
                Scan.id.desc()
            )
            .first()
        )

        # Same day + same result = duplicate
        if (
            latest_scan
            and latest_scan.created_dtm.date() == datetime.now().date()
            and latest_scan.result_fingerprint == result_fingerprint):
            
            existing_findings = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .all()
            )
            existing_findings_data = [
                {
                    "code": finding.finding_code,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "evidence": finding.evidence
                }
            for finding in existing_findings
            ]

            existing_summary = build_summary(existing_findings_data)

            return {
                "id": latest_scan.id,
                "domain": latest_scan.domain,
                "status": latest_scan.status,
                "security_score": latest_scan.security_score,
                "summary": existing_summary,
                "findings": existing_findings_data,
                "message": "No changes detected since the previous scan."
            }

    finally:
        db.close()

    # Build findings
    findings = build_findings(
        https_result,
        headers_result,
        cookies_result
    )

    security_score = calculate_security_score(findings)
    summary = build_summary(findings)

    # Save scan
    db = SessionLocal()
    try:
        scan = Scan(
        domain=domain,
        status="COMPLETED",
        security_score=security_score,
        result_fingerprint=result_fingerprint,
        canonical_domain=canonical_domain,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan_id = scan.id

        # Save findings
        for finding_data in findings:
            finding = Finding(
                scan_id=scan_id,
                finding_code=finding_data["code"],
                title=finding_data["title"],
                severity=finding_data["severity"],
                status=finding_data["status"],
                description=finding_data["description"],
                recommendation=finding_data["recommendation"],
                evidence=finding_data.get("evidence")
            )

            db.add(finding)
        db.commit()
        
    finally:
        db.close()
        
    return {
        "id": scan_id,
        "domain": domain,
        "status": "COMPLETED",
        "security_score": security_score,
        "summary": summary,
        "findings": findings
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

@app.get("/dashboard", dependencies=[Depends(require_current_user)])
def get_dashboard(
    domain: str | None = Query(default=None),
    days: int | None = Query(default=None, ge=1)
):
    db = SessionLocal()

    try:
        # Base query
        query = db.query(Scan)

        # Apply filters first
        if domain:
            query = query.filter(Scan.domain == domain)

        if days:
            start_date = datetime.now() - timedelta(days=days)
            query = query.filter(Scan.created_dtm >= start_date)

        # Filtered total
        total_scans = query.count()

        # Filtered latest scan
        latest_scan = (
            query
            .order_by(Scan.created_dtm.desc(), Scan.id.desc())
            .first()
        )

        # Filtered scans
        scans = (
            query
            .order_by(Scan.created_dtm.desc(), Scan.id.desc())
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
        # Keep this unfiltered so frontend can populate
        # the domain dropdown with all available domains.
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