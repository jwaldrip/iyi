"""Download a GitHub Actions artifact archive without forwarding the API token."""
import urllib.error
import urllib.request

REDIRECT_CODES = (301, 302, 303, 307, 308)
USER_AGENT = "iyi-strict-independent-readback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_artifact_zip(artifact_url, token, timeout=60):
    """Return the zip bytes of one artifact archive.

    The REST endpoint answers with a redirect to a short-lived signed blob URL.
    urllib copies the Authorization header onto that redirect, and the storage
    host rejects it with 401. The redirect is therefore followed here, and only
    the API request carries the token.
    """
    request = urllib.request.Request(artifact_url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as err:
        location = err.headers.get("Location") if err.code in REDIRECT_CODES else None
        if location is None:
            raise
    signed = urllib.request.Request(location, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(signed, timeout=timeout) as response:
        return response.read()
