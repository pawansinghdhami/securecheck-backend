import socket
import requests
from scanners.http_client import get

def check_domain_reachability(domain: str) -> dict:
    # Step 1: DNS resolution
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {
            "reachable": False,
            "stage": "DNS",
            "ip_address": None,
            "status_code": None,
            "final_url": None,
            "error": f"DNS resolution failed: {str(e)}"
        }
    except Exception as e:
        return {
            "reachable": False,
            "stage": "DNS",
            "ip_address": None,
            "status_code": None,
            "final_url": None,
            "error": str(e)
        }

    # Step 2: HTTPS connectivity
    try:
        response = get(
        f"https://{domain}",
        timeout=10
        )

        return {
            "reachable": True,
            "stage": "HTTPS",
            "ip_address": ip_address,
            "status_code": response.status_code,
            "final_url": response.url,
            "error": None
        }

    except requests.RequestException as e:
        return {
            "reachable": False,
            "stage": "HTTPS",
            "ip_address": ip_address,
            "status_code": None,
            "final_url": None,
            "error": f"HTTPS connection failed: {str(e)}"
        }