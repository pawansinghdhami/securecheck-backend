import json
import hashlib

def generate_scan_fingerprint(
    https_result,
    headers_result,
    cookies_result):

    data = {
        "https" : https_result,
        "headers" : headers_result,
        "cookies" : cookies_result
    }

    normalized_data = json.dumps(
        data,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        normalized_data.encode("utf-8")
    ).hexdigest()