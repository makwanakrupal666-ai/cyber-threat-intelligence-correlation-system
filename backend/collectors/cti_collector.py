from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


def fetch_cti_text(url, timeout=10):
    """
    Fetch publicly accessible CTI text from a URL.

    The response is treated as untrusted input and is returned
    only as text. It is never executed.
    """

    request = Request(
        url,
        headers={
            "User-Agent": "CTI-Research-Collector/1.0"
        }
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get(
                "Content-Type",
                ""
            )

            raw_data = response.read()

            text = raw_data.decode(
                "utf-8",
                errors="replace"
            )

            return {
                "url": url,
                "content_type": content_type,
                "text": text
            }

    except HTTPError as error:
        raise RuntimeError(
            f"CTI source returned HTTP {error.code}"
        ) from error

    except URLError as error:
        raise RuntimeError(
            f"Unable to reach CTI source: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise RuntimeError(
            "CTI source request timed out"
        ) from error