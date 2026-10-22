from backend.collectors.cti_collector import fetch_cti_text


class FakeHeaders:
    def get(self, name, default=""):
        if name == "Content-Type":
            return "text/plain"

        return default


class FakeResponse:
    headers = FakeHeaders()

    def read(self):
        return b"Malicious IP: 185.10.20.30"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass


def test_fetch_cti_text(monkeypatch):
    def fake_urlopen(request, timeout=10):
        return FakeResponse()

    monkeypatch.setattr(
        "backend.collectors.cti_collector.urlopen",
        fake_urlopen
    )

    result = fetch_cti_text(
        "https://example.com/cti.txt"
    )

    assert result["url"] == "https://example.com/cti.txt"
    assert result["content_type"] == "text/plain"
    assert "185.10.20.30" in result["text"]