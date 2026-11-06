import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import requests

from urlcheck import urlcheck
from urlcheck.urlcheck import Result, Status, check, extract_urls, obfuscate, report

UP = Status(200, "ACTIVE (HTTP CODE)", alive=True)
DOWN = Status(404, "INACTIVE (HTTP CODE)", alive=False)


def test_report_actions_per_url():
    text = report(
        [
            Result("http://bad.example/up.php", True, ["MALWARE"], UP),
            Result("http://bad.example/gone.php", True, ["MALWARE"], DOWN),
            Result("http://bad.example", True, [], UP),
            Result("http://fine.example/", False, [], UP),
        ]
    )
    assert "Remove content from /up.php" in text
    assert "Request a review from Google." in text
    assert "Remove content from /\n" in text
    assert "None.  OK" in text
    assert "case has been closed" not in text


def test_report_closes_case_when_nothing_needs_removal():
    text = report(
        [
            Result("http://fine.example/", False, [], UP),
            Result("http://x.example/a", True, [], DOWN),
        ]
    )
    assert "case has been closed" in text


def test_unknown_status_code_is_not_a_crash():
    text = report(
        [Result("http://bad.example/a", True, [], Status(None, "INVALID (SYNTAX)", alive=True))]
    )
    assert "Remove content from /a" in text
    assert "n/a - INVALID (SYNTAX)" in text


def test_extract_urls_refangs_and_skips_unparseable():
    urls = set(extract_urls("see hxxp://evil[.]example/x and http://host:abc/ here"))
    assert urls == {"http://evil.example/x"}


def test_obfuscate_only_touches_scheme():
    assert obfuscate("https://myhttpsite.com/a") == "hxxps://myhttpsite[.]com/a"


def test_check_survives_failures():
    result = Result("http://bad.example/", True)
    with (
        mock.patch.object(urlcheck, "get_url_status", side_effect=RuntimeError("boom")),
        mock.patch.object(urlcheck.requests, "post", side_effect=requests.Timeout()),
    ):
        check(result, "key")
    assert result.status.code is None
    assert result.status.alive
    assert result.urlscan is None


def test_threads_do_not_mix_up_statuses():
    def fake_checker(**_):
        checker = mock.Mock()
        checker.set_subject.side_effect = lambda url: setattr(checker, "url", url)

        def get_status():
            time.sleep(0.001)  # widen the window a shared checker would race in
            code = 200 if "up" in checker.url else 404
            return mock.Mock(http_status_code=code, status="ACTIVE", status_source="HTTP CODE")

        checker.get_status.side_effect = get_status
        return checker

    results = [
        Result(f"http://{kind}{i}.example/", True) for i in range(50) for kind in ("up", "down")
    ]
    with (
        mock.patch.object(urlcheck, "URLAvailabilityChecker", side_effect=fake_checker),
        ThreadPoolExecutor(16) as pool,
    ):
        list(pool.map(lambda r: check(r, None), results))
    assert all(r.status.alive == ("up" in r.url) for r in results)
