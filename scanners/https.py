import requests

def check_https(domain: str):

    url = f"https://{domain}"

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        return {
            "domain": domain,
            "check": "HTTPS",
            "status": "PASS",
            "severity": "NONE",
            "title": "HTTPS is enabled",
            "description": "The website is accessible over HTTPS.",
            "recommendation": "No action required.",
            "evidence": {
                "final_url": response.url,
                "status_code": response.status_code
            }
        }

    except requests.exceptions.RequestException as e:

        return {
            "domain": domain,
            "check": "HTTPS",
            "status": "FAIL",
            "severity": "HIGH",
            "title": "HTTPS connection failed",
            "description": "The website could not be accessed securely over HTTPS.",
            "recommendation": "Configure a valid HTTPS certificate and ensure the website is accessible over HTTPS.",
            "evidence": {
                "error": str(e)
            }
        }