from __future__ import annotations

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
FIREFOX_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
    "Gecko/20100101 Firefox/120.0"
)


def test_fingerprint_report_chrome():
    from masktunnel import get_fingerprint_report

    report = get_fingerprint_report(CHROME_UA)

    assert report["UserAgent"] == CHROME_UA
    assert report["Browser"] == "Chrome"
    assert report["TLSProfile"] == "133"
    assert report["JA3"].startswith("771,")
    assert len(report["JA3Hash"]) == 32
    assert report["JA4"].startswith("t13d")
    assert report["AkamaiFingerprint"].count("|") == 3
    assert len(report["AkamaiHash"]) == 32


def test_fingerprint_report_firefox_differs_from_chrome():
    from masktunnel import get_fingerprint_report

    chrome = get_fingerprint_report(CHROME_UA)
    firefox = get_fingerprint_report(FIREFOX_UA)

    assert firefox["Browser"] == "Firefox"
    assert firefox["JA3"] != chrome["JA3"]
    assert firefox["JA4"] != chrome["JA4"]


def test_fingerprint_report_defaults_to_chrome():
    from masktunnel import get_fingerprint_report

    report = get_fingerprint_report("")

    assert report["Browser"] == "Chrome"
    assert report["JA4"].startswith("t13d")
