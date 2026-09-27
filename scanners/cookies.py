import requests

def check_cookie_security(domain: str):
    url = f"https://{domain}"

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )
        cookies = []
        for cookie in response.cookies:
            cookies.append({
                "name" : cookie.name,
                "secure" : cookie.secure,
                "httponly" : cookie._rest.get("HttpOnly", False),
                "samesite" : cookie._rest.get("SameSite")
            })

        return {
            "domain" : domain,
            "check"  : "COOKIE_SECURITY",
            "status" : "COMPLETED",
            "final_url" : response.url,
            "cookies" : cookies
        }
    except requests.exceptions.RequestException as e:
        return {
            "domain": domain,
            "check": "COOKIE_SECURITY",
            "status": "ERROR",
            "message": "Unable to connect to the website.",
            "error": str(e)
        }