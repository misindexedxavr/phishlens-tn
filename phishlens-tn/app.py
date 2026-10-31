"""PhishLens TN web application (Flask).

Run:  python app.py        (development, 127.0.0.1:5000)
      gunicorn "app:create_app()"   (production, see README)
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from analyzer import __version__
from analyzer.errors import PhishLensError
from analyzer.netsafe import check_url
from analyzer.pipeline import STEPS, analyze_url, iter_analysis
from analyzer.report import render_markdown
from analyzer.scoring import LEVELS, get_rules
from ratelimit import RateLimiter

log = logging.getLogger("phishlens")


def _parse_limit(value: str, default: tuple[int, float]) -> tuple[int, float]:
    """Parse 'COUNT/SECONDS' (for example '10/60')."""
    try:
        count, window = value.split("/")
        return max(1, int(count)), max(1.0, float(window))
    except (ValueError, AttributeError):
        return default


def create_app(config: dict[str, Any] | None = None) -> Flask:
    """Application factory."""
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=1_000_000,  # export bodies only; analysis input is a short URL
        ANALYZE_LIMIT=os.environ.get("PHISHLENS_ANALYZE_LIMIT", "10/60"),
        EXPORT_LIMIT=os.environ.get("PHISHLENS_EXPORT_LIMIT", "30/60"),
        MAX_CONCURRENT_ANALYSES=int(os.environ.get("PHISHLENS_MAX_CONCURRENT", "4")),
        USE_RDAP=os.environ.get("PHISHLENS_RDAP", "1") != "0",
        TRUSTED_PROXIES=int(os.environ.get("PHISHLENS_TRUSTED_PROXIES", "0")),
    )
    if config:
        app.config.update(config)
    app.json.sort_keys = False  # type: ignore[attr-defined]
    if app.config["TRUSTED_PROXIES"]:
        n = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)  # type: ignore[method-assign]

    analyze_count, analyze_window = _parse_limit(str(app.config["ANALYZE_LIMIT"]), (10, 60.0))
    export_count, export_window = _parse_limit(str(app.config["EXPORT_LIMIT"]), (30, 60.0))
    limiters = {
        "analyze": RateLimiter(analyze_count, analyze_window),
        "export": RateLimiter(export_count, export_window),
    }
    slots = threading.BoundedSemaphore(max(1, int(app.config["MAX_CONCURRENT_ANALYSES"])))

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def api_error(code: str, message: str, status: int, hint: str = "", headers: dict[str, str] | None = None) -> Response:
        response = jsonify(error={"code": code, "message": message, "hint": hint})
        response.status_code = status
        for key, value in (headers or {}).items():
            response.headers[key] = value
        return response

    def rate_limited(bucket: str) -> Response | None:
        allowed, retry = limiters[bucket].hit(request.remote_addr or "unknown")
        if allowed:
            return None
        return api_error(
            "rate_limited", "Too many requests. Please slow down.", 429,
            f"Try again in {retry} second(s).", {"Retry-After": str(retry)},
        )

    def read_url() -> tuple[str | None, Response | None]:
        if not request.is_json:
            return None, api_error("invalid_request", "Send a JSON body such as {\"url\": \"https://example.com\"}.", 415)
        data = request.get_json(silent=True)
        url = data.get("url") if isinstance(data, dict) else None
        if not isinstance(url, str):
            return None, api_error("invalid_request", "The request must include a 'url' string.", 400)
        return url, None

    def preflight(url: str) -> Response | None:
        """Validate the URL (and its DNS answer) before work starts so errors use real HTTP codes."""
        try:
            check_url(url)
        except PhishLensError as exc:
            if exc.code == "host_unresolved":
                return None  # let the pipeline report it with the right step
            return api_error(exc.code, exc.message, exc.http_status, exc.hint)
        return None

    # ------------------------------------------------------------------ #
    # pages
    # ------------------------------------------------------------------ #
    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {"year": datetime.now(timezone.utc).year, "version": __version__}

    @app.get("/")
    def index() -> str:
        return render_template("index.html", steps=STEPS)

    @app.get("/about")
    def about() -> str:
        rules = sorted(get_rules(), key=lambda r: (-r.weight, r.title))
        return render_template("about.html", rules=rules, levels=LEVELS)

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify(status="ok", version=__version__)

    # ------------------------------------------------------------------ #
    # API
    # ------------------------------------------------------------------ #
    @app.get("/api/rules")
    def api_rules() -> Response:
        return jsonify(
            rules=[
                {"id": r.id, "title": r.title, "weight": r.weight, "category": r.category, "description": r.description}
                for r in get_rules()
            ],
            levels=[{"level": name, "min_score": minimum} for name, minimum in LEVELS],
        )

    @app.post("/api/analyze")
    def api_analyze() -> Response:
        limited = rate_limited("analyze")
        if limited:
            return limited
        url, bad = read_url()
        if bad or url is None:
            return bad  # type: ignore[return-value]
        blocked = preflight(url)
        if blocked:
            return blocked
        if not slots.acquire(blocking=False):
            return api_error("busy", "The analyzer is busy right now.", 503, "Try again in a few seconds.", {"Retry-After": "5"})
        try:
            result = analyze_url(url, use_rdap=app.config["USE_RDAP"])
        except PhishLensError as exc:
            return api_error(exc.code, exc.message, exc.http_status, exc.hint)
        finally:
            slots.release()
        return jsonify(result)

    @app.post("/api/analyze/stream")
    def api_analyze_stream() -> Response:
        limited = rate_limited("analyze")
        if limited:
            return limited
        url, bad = read_url()
        if bad or url is None:
            return bad  # type: ignore[return-value]
        blocked = preflight(url)
        if blocked:
            return blocked
        if not slots.acquire(blocking=False):
            return api_error("busy", "The analyzer is busy right now.", 503, "Try again in a few seconds.", {"Retry-After": "5"})

        use_rdap = app.config["USE_RDAP"]

        def generate():
            try:
                for event in iter_analysis(url, use_rdap=use_rdap):
                    yield json.dumps(event, ensure_ascii=False) + "\n"
            finally:
                slots.release()

        return Response(
            stream_with_context(generate()),
            mimetype="application/x-ndjson",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"},
        )

    @app.post("/api/export/<fmt>")
    def api_export(fmt: str) -> Response:
        limited = rate_limited("export")
        if limited:
            return limited
        if fmt not in ("json", "markdown", "md"):
            return api_error("invalid_request", "Supported export formats: json, markdown.", 404)
        data = request.get_json(silent=True) if request.is_json else None
        if not isinstance(data, dict) or data.get("schema") != "phishlens-tn/analysis@1":
            return api_error("invalid_request", "Send an analysis result produced by PhishLens TN.", 400)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
        if fmt == "json":
            body, mimetype, ext = json.dumps(data, indent=2, ensure_ascii=False), "application/json", "json"
        else:
            body, mimetype, ext = render_markdown(data), "text/markdown", "md"
        return Response(
            body, mimetype=mimetype,
            headers={"Content-Disposition": f'attachment; filename="phishlens-{stamp}.{ext}"'},
        )

    # ------------------------------------------------------------------ #
    # security headers and error handling
    # ------------------------------------------------------------------ #
    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    def render_error(status: int, title: str, message: str) -> Response | tuple[str, int]:
        if request.path.startswith("/api/"):
            return api_error("http_error", message, status)
        return render_template("error.html", status=status, title=title, message=message), status

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        titles = {404: "Page not found", 405: "Method not allowed", 413: "Request too large"}
        return render_error(exc.code or 500, titles.get(exc.code or 500, "Request problem"), exc.description or "The request could not be processed.")

    @app.errorhandler(Exception)
    def unhandled(exc: Exception):
        log.exception("Unhandled error")  # details stay in the server log
        return render_error(500, "Something went wrong", "An unexpected error occurred. Please try again.")

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False, threaded=True)
