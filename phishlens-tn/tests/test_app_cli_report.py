"""Web API, rate limiting, report rendering and the batch CLI."""
from __future__ import annotations

import csv
import json
import threading

import pytest

import app as app_module
import cli
from analyzer.report import csv_safe, defang, md_escape, render_batch_markdown, render_markdown, result_to_csv_row
from ratelimit import RateLimiter

from conftest import fixture_text

PHISH_URL = "https://biatt-login.example.com/connexion"


@pytest.fixture
def phishing_result(run_offline):
    return run_offline(PHISH_URL, fixture_text("phishing_bank_login.html"))


@pytest.fixture
def client(fake_dns):
    application = app_module.create_app({"TESTING": True, "ANALYZE_LIMIT": "100/60", "USE_RDAP": False})
    return application.test_client()


# ----- web pages ---------------------------------------------------------------
@pytest.mark.parametrize("path", ["/", "/about", "/does-not-exist"])
def test_every_page_has_footer_and_warning(client, path):
    html = client.get(path).get_data(as_text=True)
    assert "Built by Xavyr" in html and "Never open suspicious links in your normal browser." in html


def test_security_headers_and_health(client):
    response = client.get("/healthz")
    assert response.json["status"] == "ok"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"] and response.headers["X-Content-Type-Options"] == "nosniff"


def test_index_has_examples_and_steps(client):
    html = client.get("/").get_data(as_text=True)
    assert html.count("data-example=") == 3 and 'data-step="fetch"' in html and 'data-step="score"' in html


# ----- API ----------------------------------------------------------------------
@pytest.mark.parametrize("payload,status,code", [
    ({"url": "javascript:alert(1)"}, 400, "invalid_url"),
    ({"url": ""}, 400, "invalid_url"),
    ({"url": "http://127.0.0.1/"}, 403, "blocked_address"),
    ({"url": "http://localhost:5000"}, 403, "blocked_address"),
    ({"url": "http://169.254.169.254/latest/meta-data"}, 403, "blocked_address"),
    ({"nope": 1}, 400, "invalid_request"),
])
def test_api_rejects_bad_input(client, payload, status, code):
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == status and response.json["error"]["code"] == code
    assert "Traceback" not in response.get_data(as_text=True)


def test_api_requires_json(client):
    assert client.post("/api/analyze", data="url=http://example.com").status_code == 415


def test_api_analyze_and_stream(client, monkeypatch, phishing_result):
    monkeypatch.setattr(app_module, "analyze_url", lambda url, **kw: phishing_result)
    response = client.post("/api/analyze", json={"url": PHISH_URL})
    assert response.status_code == 200 and response.json["level"] == "Critical"

    events = [{"event": "step", "step": "fetch", "status": "running", "detail": ""}, {"event": "result", "result": phishing_result}]
    monkeypatch.setattr(app_module, "iter_analysis", lambda url, **kw: iter(events))
    stream = client.post("/api/analyze/stream", json={"url": PHISH_URL})
    lines = [json.loads(line) for line in stream.get_data(as_text=True).splitlines()]
    assert stream.mimetype == "application/x-ndjson" and [e["event"] for e in lines] == ["step", "result"]


def test_api_maps_pipeline_errors_without_traces(client, monkeypatch):
    from analyzer.errors import FetchTimeoutError

    def boom(url, **kw):
        raise FetchTimeoutError("The server did not answer within 10 seconds.")

    monkeypatch.setattr(app_module, "analyze_url", boom)
    response = client.post("/api/analyze", json={"url": "https://slow.example.com"})
    assert response.status_code == 504 and response.json["error"]["code"] == "timeout"


def test_unexpected_exceptions_are_hidden(client, monkeypatch):
    monkeypatch.setattr(app_module, "analyze_url", lambda url, **kw: 1 / 0)
    response = client.post("/api/analyze", json={"url": "https://slow.example.com"})
    assert response.status_code == 500 and "division" not in response.get_data(as_text=True)


def test_rate_limit_returns_429(fake_dns, monkeypatch, phishing_result):
    monkeypatch.setattr(app_module, "analyze_url", lambda url, **kw: phishing_result)
    limited = app_module.create_app({"TESTING": True, "ANALYZE_LIMIT": "2/60"}).test_client()
    codes = [limited.post("/api/analyze", json={"url": PHISH_URL}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert "Retry-After" in limited.post("/api/analyze", json={"url": PHISH_URL}).headers


def test_busy_when_all_slots_taken(fake_dns, monkeypatch):
    busy = app_module.create_app({"TESTING": True, "MAX_CONCURRENT_ANALYSES": 1, "ANALYZE_LIMIT": "100/60"})
    release, entered = threading.Event(), threading.Event()

    def slow(url, **kw):
        entered.set()
        release.wait(5)
        return {"score": 0}

    monkeypatch.setattr(app_module, "analyze_url", slow)
    first = threading.Thread(target=lambda: busy.test_client().post("/api/analyze", json={"url": PHISH_URL}))
    first.start()
    assert entered.wait(5)
    assert busy.test_client().post("/api/analyze", json={"url": PHISH_URL}).status_code == 503
    release.set()
    first.join()


def test_export_endpoints(client, phishing_result):
    md = client.post("/api/export/markdown", json=phishing_result)
    assert md.status_code == 200 and md.mimetype == "text/markdown" and "attachment" in md.headers["Content-Disposition"]
    body = md.get_data(as_text=True)
    assert "## Signals" in body and "hxxps://biatt-login[.]example[.]com" in body and "https://biatt-login" not in body
    exported = client.post("/api/export/json", json=phishing_result)
    assert json.loads(exported.get_data(as_text=True))["score"] == phishing_result["score"]
    assert client.post("/api/export/markdown", json={"hello": 1}).status_code == 400
    assert client.post("/api/export/pdf", json=phishing_result).status_code == 404


# ----- rate limiter / report helpers -----------------------------------------------
def test_rate_limiter_window():
    now = [0.0]
    limiter = RateLimiter(2, 10, clock=lambda: now[0])
    assert limiter.hit("a") == (True, 0) and limiter.hit("a") == (True, 0)
    allowed, retry = limiter.hit("a")
    assert not allowed and retry == 10 and limiter.hit("b")[0]
    now[0] = 10.5
    assert limiter.hit("a")[0]


def test_defang_and_escaping():
    assert defang("https://evil.example.com/a.b?x=1") == "hxxps://evil[.]example[.]com/a.b?x=1"
    assert "<" not in md_escape("<script>|*x*</script>").replace("\\<", "") and "\n" not in md_escape("a\nb")
    assert csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)" and csv_safe("ok") == "ok"


def test_markdown_report_sections(phishing_result):
    md = render_markdown(phishing_result)
    for heading in ("## Signals", "## Domain", "## Certificate", "## Redirect chain", "## Forms", "## External domains"):
        assert heading in md
    assert md.rstrip().endswith("Built by Xavyr._")


def test_markdown_report_tolerates_garbage():
    assert "PhishLens TN report" in render_markdown({"schema": "x", "signals": "oops", "page": []})


# ----- CLI batch ----------------------------------------------------------------------
def test_batch_cli_writes_json_csv_and_markdown(tmp_path, monkeypatch, phishing_result):
    urls = tmp_path / "urls.txt"
    urls.write_text("# comment\n\nhttps://example.com\nhttps://example.com\nhttp://127.0.0.1/\nhttps://biatt-login.example.com/connexion\n")
    assert cli.read_url_file(urls) == ["https://example.com", "http://127.0.0.1/", "https://biatt-login.example.com/connexion"]

    def fake(url, use_rdap):
        if "127.0.0.1" in url:
            return {"url": url, "error": {"code": "blocked_address", "message": "blocked", "hint": ""}}
        return dict(phishing_result, url=url) if "biatt" in url else dict(phishing_result, url=url, score=0, level="Low", signals=[], brands={"targeted_brands": []})

    monkeypatch.setattr(cli, "analyze_one", fake)
    out = tmp_path / "out"
    assert cli.main(["batch", str(urls), "--out-dir", str(out), "--workers", "2", "--no-rdap"]) == 0
    data = json.loads((out / "results.json").read_text())
    assert len(data) == 3
    rows = list(csv.DictReader((out / "results.csv").open()))
    assert [r["status"] for r in rows] == ["ok", "error", "ok"] and rows[2]["level"] == "Critical" and "blocked_address" in rows[1]["error"]
    summary = (out / "summary.md").read_text()
    assert "Average score" in summary and "BIAT" in summary and "Most common tricks" in summary and "hxxp" in summary


def test_batch_summary_numbers(phishing_result):
    items = [dict(phishing_result), dict(phishing_result, score=20, level="Low", signals=[], brands={"targeted_brands": []}), {"url": "x", "error": {"message": "m"}}]
    summary = render_batch_markdown(items)
    expected = (phishing_result["score"] + 20) / 2
    assert f"{expected:.1f}/100" in summary and "2 of 3" in summary
    assert result_to_csv_row(items[2])["status"] == "error"


def test_cli_missing_file(tmp_path):
    assert cli.main(["batch", str(tmp_path / "missing.txt")]) == 2


def test_cli_rules_lists_levels(capsys):
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "Critical >= 75" in out and "typosquatting" in out
