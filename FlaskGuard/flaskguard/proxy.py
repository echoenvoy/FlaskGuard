import logging

import requests
from flask import Response, request
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

RESPONSE_EXCLUDED_HEADERS = HOP_BY_HOP_HEADERS | {
    "content-encoding",
    "content-length",
}


def _error_response(message: str, status: int):
    return Response(
        message,
        status=status,
        content_type="text/plain; charset=utf-8",
    )


def _proxy_timeout(timeout):
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = 10.0
    return max(timeout, 0.1)


def _proxy_verify_tls(verify_tls):
    if isinstance(verify_tls, str):
        return verify_tls.strip().lower() not in {"0", "false", "no", "off"}
    return bool(verify_tls)


def forward_request(backend_url: str, path: str, timeout=10, verify_tls=True):
    """
    Forwards the incoming Flask request to the backend server.
    Streams the response back to the client.
    """
    # 1. Construct target URL
    # Normalize backend_url and append the path
    target_url = f"{backend_url.rstrip('/')}/{path.lstrip('/')}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    # 2. Extract client headers and exclude hop-by-hop / host headers
    # requests library recalculates host and content-length automatically.
    headers = {
        key: value
        for key, value in request.headers
        if key.lower() not in (HOP_BY_HOP_HEADERS | {"host", "content-length"})
    }

    # Add standard reverse proxy headers
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        headers['X-Forwarded-For'] = f"{x_forwarded_for}, {request.remote_addr}"
    else:
        headers['X-Forwarded-For'] = request.remote_addr

    headers['X-Forwarded-Proto'] = request.scheme
    headers['X-Forwarded-Host'] = request.headers.get('Host', '')

    # 3. Read body data
    data = request.get_data()

    # 4. Forward the request to backend
    try:
        verify = _proxy_verify_tls(verify_tls)
        if not verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        # stream=True allows us to pipe the response body chunk-by-chunk
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=data,
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            timeout=_proxy_timeout(timeout),
            verify=verify,
        )

        # 5. Extract response headers, excluding HTTP hop-by-hop headers
        resp_headers = [
            (name, value) for name, value in resp.raw.headers.items()
            if name.lower() not in RESPONSE_EXCLUDED_HEADERS
        ]

        # 6. Stream content back to the client
        def generate():
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            finally:
                resp.close()

        return Response(
            generate(),
            status=resp.status_code,
            headers=resp_headers
        )

    except requests.exceptions.Timeout as exc:
        logger.warning("Backend request timed out for %s: %s", target_url, exc)
        return _error_response("Gateway Timeout: backend server did not respond in time.", 504)
    except requests.exceptions.ConnectionError as exc:
        logger.warning("Backend connection failed for %s: %s", target_url, exc)
        return _error_response("Bad Gateway: backend server is unavailable.", 502)
    except requests.exceptions.RequestException as exc:
        logger.warning("Backend proxy request failed for %s: %s", target_url, exc)
        return _error_response("Bad Gateway: proxy request failed.", 502)
