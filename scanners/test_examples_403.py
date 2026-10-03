import requests


URL = "https://examples.com"


def test_request(name, headers=None):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    try:
        response = requests.get(
            URL,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )

        print("Status Code :", response.status_code)
        print("Final URL   :", response.url)
        print("History     :", [
            f"{r.status_code} -> {r.headers.get('location')}"
            for r in response.history
        ])

        print("\nRequest Headers:")
        for key, value in response.request.headers.items():
            print(f"  {key}: {value}")

        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        print("\nResponse Size:", len(response.content))

        print("\nResponse Body Preview:")
        print(response.text[:500])

    except requests.RequestException as e:
        print("REQUEST FAILED")
        print(type(e).__name__)
        print(str(e))


# ---------------------------------------------------------
# Test 1: requests default
# ---------------------------------------------------------

test_request(
    "TEST 1 - Requests Default"
)


# ---------------------------------------------------------
# Test 2: Transparent SecureCheck User-Agent
# ---------------------------------------------------------

test_request(
    "TEST 2 - SecureCheck User-Agent",
    headers={
        "User-Agent": "SecureCheck/1.0"
    }
)


# ---------------------------------------------------------
# Test 3: Normal browser-style headers
# ---------------------------------------------------------

test_request(
    "TEST 3 - Browser-style Standard Headers",
    headers={
        "User-Agent": "SecureCheck/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
)