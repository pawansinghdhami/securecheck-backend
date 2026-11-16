import requests


SECURECHECK_HEADERS = {
    "User-Agent": "SecureCheck/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def get(url: str, timeout: int = 10) -> requests.Response:
    return requests.get(
        url,
        headers=SECURECHECK_HEADERS,
        timeout=timeout,
        allow_redirects=True,
    )