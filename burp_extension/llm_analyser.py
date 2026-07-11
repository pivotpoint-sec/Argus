# -*- coding: utf-8 -*-
"""
Argus - Burp Suite Python (Jython 2.7) extension entry point.

Uses the LEGACY IBurpExtender API because Jython cannot consume the
Montoya API (Montoya is Java-only). For every proxy/repeater/scanner
request/response pair, we POST a JSON payload to the local Argus bridge
(default http://127.0.0.1:8765/analyse) and annotate the Burp item with
the result.

The extension NEVER blocks Burp's HTTP threads, NEVER raises into Burp,
and NEVER talks to a remote endpoint - only the local bridge.

Auth token: read from environment variable ARGUS_TOKEN, OR from a sibling
argus_config.json file. Must match config.yaml -> auth.token on the bridge.
"""
from __future__ import print_function

import json
import os
import threading
import traceback

try:
    from urllib2 import Request, urlopen, URLError, HTTPError  # Jython 2 / Py2
except ImportError:                                              # CPython 3
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError

# Burp legacy extender API (provided by Burp at load time).
from burp import IBurpExtender, IHttpListener


# ---------------------------------------------------------------------------
# Configuration - edit AUTH_TOKEN below OR set env var ARGUS_TOKEN OR drop an
# argus_config.json next to this file with {"auth_token": "...", "bridge_url": "..."}
# ---------------------------------------------------------------------------

BRIDGE_URL = "http://127.0.0.1:8765/analyse"
BRIDGE_TIMEOUT_SECONDS = 60
AUTH_TOKEN = "change-me-before-first-run"
EXTENSION_NAME = "Argus - local LLM triage"

# Burp tool flags from IBurpExtenderCallbacks (legacy constants).
TOOL_PROXY    = 0x4
TOOL_REPEATER = 0x40
TOOL_SCANNER  = 0x10
TOOL_INTRUDER = 0x20

# Which tools we analyse (proxy responses + repeater repeats by default).
ANALYSE_TOOLS = TOOL_PROXY | TOOL_REPEATER

try:
    _cfg_path = os.path.join(os.path.dirname(__file__), "argus_config.json")
    if os.path.exists(_cfg_path):
        with open(_cfg_path, "r") as _fh:
            _cfg = json.load(_fh) or {}
        BRIDGE_URL = _cfg.get("bridge_url", BRIDGE_URL)
        AUTH_TOKEN = _cfg.get("auth_token", AUTH_TOKEN)
        BRIDGE_TIMEOUT_SECONDS = int(_cfg.get("bridge_timeout_seconds", BRIDGE_TIMEOUT_SECONDS))
    AUTH_TOKEN = os.environ.get("ARGUS_TOKEN", AUTH_TOKEN) or AUTH_TOKEN
except Exception:
    pass


# ---------------------------------------------------------------------------
# Helpers - keep them pure-Python so unit tests can exercise them.
# ---------------------------------------------------------------------------


def _post_json(payload):
    body = json.dumps(payload).encode("utf-8") if hasattr(json.dumps(payload), "encode") else bytes(json.dumps(payload))
    headers = {"Content-Type": "application/json"}
    if AUTH_TOKEN:
        headers["X-Argus-Token"] = AUTH_TOKEN
    req = Request(BRIDGE_URL, data=body, headers=headers)
    try:
        resp = urlopen(req, timeout=BRIDGE_TIMEOUT_SECONDS)
    except (HTTPError, URLError, Exception):
        return None
    try:
        raw = resp.read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return json.loads(raw)
    except Exception:
        return None


def _highlight_for(risk):
    return {
        "critical": "red",
        "high":     "orange",
        "medium":   "yellow",
        "low":      "blue",
        "none":     None,
    }.get(str(risk or "none").lower())


def _comment_for(result):
    """Render a short single-line annotation for the Burp item."""
    risk = (result or {}).get("risk", "none")
    findings = (result or {}).get("findings") or []
    if not findings:
        return "Argus[" + risk + "] no findings"
    f0 = findings[0] or {}
    parts = ["Argus[" + risk + "]"]
    if f0.get("type"):
        parts.append(str(f0["type"]))
    if f0.get("parameter"):
        parts.append("param=" + str(f0["parameter"]))
    detail = f0.get("detail") or ""
    if detail:
        parts.append("- " + detail[:120])
    return " ".join(parts)


def _bytes_to_str(b):
    if b is None:
        return ""
    try:
        return bytes(b).decode("utf-8", errors="replace")
    except Exception:
        try:
            return str(b)
        except Exception:
            return ""


def _build_payload(tool_name, request_text, response_text, url):
    return {
        "url": url,
        "tool": tool_name,
        "request": request_text,
        "response": response_text,
    }


# ---------------------------------------------------------------------------
# Burp entry point - MUST be a top-level class named BurpExtender.
# ---------------------------------------------------------------------------


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerHttpListener(self)
        out = callbacks.getStdout()
        msg = ("Argus extension ready; bridge = " + BRIDGE_URL +
               "; auth=" + ("yes" if AUTH_TOKEN else "no") + "\n")
        try:
            out.write(msg.encode("utf-8"))
        except Exception:
            print(msg)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only analyse responses (we need request + response together) and
        # only from tools the operator opted in to.
        if messageIsRequest:
            return
        if not (toolFlag & ANALYSE_TOOLS):
            return
        try:
            t = threading.Thread(
                target=self._analyse_safely,
                args=(toolFlag, messageInfo),
            )
            t.setDaemon(True)
            t.start()
        except Exception:
            # Never let an error propagate back into Burp's HTTP thread.
            try:
                self._callbacks.printError(traceback.format_exc())
            except Exception:
                pass

    # -- internals ------------------------------------------------------

    def _tool_name(self, toolFlag):
        if toolFlag & TOOL_PROXY:    return "burp-proxy"
        if toolFlag & TOOL_REPEATER: return "burp-repeater"
        if toolFlag & TOOL_SCANNER:  return "burp-scanner"
        if toolFlag & TOOL_INTRUDER: return "burp-intruder"
        return "burp"

    def _analyse_safely(self, toolFlag, messageInfo):
        try:
            req_bytes = messageInfo.getRequest()
            resp_bytes = messageInfo.getResponse()
            url_obj = messageInfo.getUrl()
            if not (req_bytes and resp_bytes and url_obj):
                return
            # Use Burp's helpers - native bytes() does NOT work on Java byte[]
            # under Jython 2.7 (it produces the JVM array repr instead).
            request_text = self._helpers.bytesToString(req_bytes)
            response_text = self._helpers.bytesToString(resp_bytes)
            payload = _build_payload(
                tool_name=self._tool_name(toolFlag),
                request_text=request_text,
                response_text=response_text,
                url=str(url_obj),
            )
            try:
                self._callbacks.getStdout().write(
                    ("Argus -> POST " + payload["url"][:80] + "\n").encode("utf-8")
                )
            except Exception:
                pass
            result = _post_json(payload)
            if not result:
                try:
                    self._callbacks.printError("Argus: bridge returned no result\n")
                except Exception:
                    pass
                return
            self._annotate(messageInfo, result)
        except Exception:
            try:
                self._callbacks.printError(traceback.format_exc())
            except Exception:
                pass

    def _annotate(self, messageInfo, result):
        try:
            comment = _comment_for(result)
            if comment:
                messageInfo.setComment(comment)
            colour = _highlight_for(result.get("risk"))
            if colour:
                messageInfo.setHighlight(colour)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CPython unit-test stub (executed only when this file is run directly,
# never under Jython at extension-load time).
# ------------------------------------------------