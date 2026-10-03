import requests
from scanners.http_client import get

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "recommendation": "Enable HSTS to force browsers to use HTTPS."
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "recommendation": "Configure a Content Security Policy appropriate for the application."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "recommendation": "Configure the X-Content-Type-Options header to prevent MIME type sniffing."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "recommendation": "Set a Referrer Policy to control the amount of referrer information sent with requests."
    }
}


def check_security_headers(domain: str):

    url = f"https://{domain}"

    try:
        response = get(
            url,
            timeout=10
        )

        results = []

        for header, config in SECURITY_HEADERS.items():

            if header in response.headers:
                results.append({
                    "header": header,
                    "status": "PASS",
                    "severity": "NONE",
                    "value": response.headers[header]
                })

            else:
                results.append({
                    "header": header,
                    "status": "FAIL",
                    "severity": config["severity"],
                    "value": None,
                    "recommendation": config["recommendation"]
                })

        return {
            "domain": domain,
            "check": "SECURITY_HEADERS",
            "status": "COMPLETED",
            "final_url": response.url,
            "headers": results
        }

    except requests.exceptions.RequestException as e:

        return {
            "domain": domain,
            "check": "SECURITY_HEADERS",
            "status": "ERROR",
            "message": "Unable to connect to the website.",
            "error": str(e)
        }