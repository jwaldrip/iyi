"""Download a GitHub Actions artifact archive without forwarding the API token."""
from __future__ import annotations

import io
import re
from typing import Iterator, Optional, Sequence
import urllib.error
import urllib.parse
import urllib.request

REDIRECT_CODES = (301, 302, 303, 307, 308)
USER_AGENT = "iyi-strict-independent-readback"
DEFAULT_TRUSTED_API_HOSTS = ("api.github.com",)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_credentialed_artifact_url(
    url: str,
    trusted_hosts: Sequence[str] = DEFAULT_TRUSTED_API_HOSTS,
) -> None:
    """Validate that initial artifact URL points to a trusted HTTPS API endpoint before sending credentials."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Invalid artifact URL scheme: {parsed.scheme!r}")
    hostname = parsed.hostname or ""
    is_loopback = hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError(f"Credentialed API request must use HTTPS: {url!r}")
    if hostname not in trusted_hosts and not is_loopback:
        raise ValueError(f"Untrusted host for credentialed API request: {hostname!r}")
    clean_path = parsed.path.rstrip("/")
    if not (re.search(r"/actions/artifacts/\d+/zip$", clean_path) or clean_path.endswith("/zip")):
        raise ValueError(f"Invalid artifact download endpoint path: {parsed.path!r}")


def download_artifact_stream(
    artifact_url: str,
    token: str,
    timeout: int = 60,
    max_bytes: int | None = None,
    chunk_size: int = 65536,
    opener: urllib.request.OpenerDirector | None = None,
    trusted_hosts: Sequence[str] = DEFAULT_TRUSTED_API_HOSTS,
) -> Iterator[bytes]:
    """Stream the bytes of one artifact archive following redirects without forwarding the token.

    Enforces max_bytes limit if specified; raises ValueError if exceeded.
    Validates initial URL host before sending credentials to prevent token exfiltration.
    """
    validate_credentialed_artifact_url(artifact_url, trusted_hosts=trusted_hosts)

    request = urllib.request.Request(
        artifact_url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    http_opener = opener or urllib.request.build_opener(_NoRedirect)
    location = None
    try:
        with http_opener.open(request, timeout=timeout) as response:
            bytes_read = 0
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if max_bytes is not None and bytes_read > max_bytes:
                    raise ValueError(
                        f"Artifact download exceeded max_bytes={max_bytes} (read {bytes_read})"
                    )
                yield chunk
            return
    except urllib.error.HTTPError as err:
        if err.code in REDIRECT_CODES:
            location = err.headers.get("Location")
        if location is None:
            raise

    if location is None:
        raise ValueError("Missing redirect Location header")

    parsed_loc = urllib.parse.urlparse(location)
    if parsed_loc.scheme not in ("https", "http"):
        raise ValueError(f"Invalid redirect location scheme: {parsed_loc.scheme}")
    if parsed_loc.scheme != "https" and parsed_loc.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"Redirect location must use HTTPS: {location}")

    signed = urllib.request.Request(location, headers={"User-Agent": USER_AGENT})
    response_ctx = opener.open(signed, timeout=timeout) if opener is not None else urllib.request.urlopen(signed, timeout=timeout)
    with response_ctx as response:
        bytes_read = 0
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            bytes_read += len(chunk)
            if max_bytes is not None and bytes_read > max_bytes:
                raise ValueError(
                    f"Artifact download exceeded max_bytes={max_bytes} (read {bytes_read})"
                )
            yield chunk


def download_artifact_zip(
    artifact_url: str,
    token: str,
    timeout: int = 60,
    max_bytes: int | None = None,
    opener: urllib.request.OpenerDirector | None = None,
    trusted_hosts: Sequence[str] = DEFAULT_TRUSTED_API_HOSTS,
) -> bytes:
    """Return the zip bytes of one artifact archive.

    The REST endpoint answers with a redirect to a short-lived signed blob URL.
    urllib copies the Authorization header onto that redirect, and the storage
    host rejects it with 401. The redirect is therefore followed here, and only
    the API request carries the token.
    """
    chunks = []
    for chunk in download_artifact_stream(
        artifact_url=artifact_url,
        token=token,
        timeout=timeout,
        max_bytes=max_bytes,
        opener=opener,
        trusted_hosts=trusted_hosts,
    ):
        chunks.append(chunk)
    return b"".join(chunks)
