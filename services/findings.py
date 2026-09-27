HEADER_FINDING_CODES = {
    "Strict-Transport-Security": "SEC-HDR-001",
    "Content-Security-Policy": "SEC-HDR-002",
    "X-Content-Type-Options": "SEC-HDR-003",
    "Referrer-Policy": "SEC-HDR-004"
}

COOKIE_FINDING_CODES = {
    "secure": "SEC-COOKIE-001",
    "httponly": "SEC-COOKIE-002",
    "samesite": "SEC-COOKIE-003"
}

def get_header_finding_code(header):
    return HEADER_FINDING_CODES.get(
        header,
        "SEC-HDR-999"
    )

def build_findings(https_result, headers_result, cookies_result):

    findings = []

    # HTTPS finding
    if https_result["status"] == "FAIL":
        findings.append({
            "code": "SEC-HTTPS-001",
            "title": https_result["title"],
            "severity": https_result["severity"],
            "status": "FAIL",
            "description": https_result["description"],
            "recommendation": https_result["recommendation"],
            "evidence": https_result.get("evidence")
        })

    # Security headers findings
    for header in headers_result.get("headers", []):

        if header["status"] == "FAIL":
            findings.append({
                "code": get_header_finding_code(header["header"]),
                "title": f"{header['header']} header is missing",
                "severity": header["severity"],
                "status": "FAIL",
                "description": (
                    f"The {header['header']} security header "
                    "was not detected."
                    ),
                "recommendation": header["recommendation"],
                "evidence": {
                    "header": header["header"],
                    "present": False,
                    "value": header.get("value")
                    }
                })

    # Cookie security findings
    for cookie in cookies_result.get("cookies", []):

        if not cookie["secure"]:
            findings.append({
                "code": f"{COOKIE_FINDING_CODES['secure']}:{cookie['name']}",
                "title": f"Secure flag missing for cookie: {cookie['name']}",
                "severity": "MEDIUM",
                "status": "FAIL",
                "description": (
                    f"The cookie '{cookie['name']}' "
                    "does not have the Secure flag."
                ),
                "recommendation": (
                    "Set the Secure attribute so the cookie "
                    "is only transmitted over HTTPS."
                ),
                "evidence": {
                    "cookie": cookie["name"],
                    "secure": cookie["secure"],
                    "httponly": cookie["httponly"],
                    "samesite": cookie["samesite"]
                    }
                })

        if not cookie["httponly"]:
            findings.append({
                "code": f"{COOKIE_FINDING_CODES['httponly']}:{cookie['name']}",
                "title": f"HttpOnly flag missing for cookie: {cookie['name']}",
                "severity": "MEDIUM",
                "status": "FAIL",
                "description": (
                    f"The cookie '{cookie['name']}' "
                    "does not have the HttpOnly flag."
                ),
                "recommendation": (
                    "Set the HttpOnly attribute to prevent "
                    "client-side scripts from accessing the cookie."
                ),
                "evidence": {
                    "cookie": cookie["name"],
                    "secure": cookie["secure"],
                    "httponly": cookie["httponly"],
                    "samesite": cookie["samesite"]
                    }
                })

        if not cookie["samesite"]:
            findings.append({
                "code": f"{COOKIE_FINDING_CODES['samesite']}:{cookie['name']}",
                "title": f"SameSite attribute missing for cookie: {cookie['name']}",
                "severity": "LOW",
                "status": "FAIL",
                "description": (
                    f"The cookie '{cookie['name']}' "
                    "does not specify a SameSite attribute."
                ),
                "recommendation": (
                    "Set an appropriate SameSite value such as "
                    "Lax or Strict."
                ),
                "evidence": {
                    "cookie": cookie["name"],
                    "secure": cookie["secure"],
                    "httponly": cookie["httponly"],
                    "samesite": cookie["samesite"]
                    }
                })  
    return findings