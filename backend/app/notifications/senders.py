"""Delivery of a message to one channel: a generic webhook, Slack, Discord or email. Pure transport: no database.

The network and mail layers are injectable (`post`, `smtp_factory`) so everything can be tested without a network.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Callable
from urllib.parse import urlparse

KINDS = ("webhook", "slack", "discord", "email")
SECURITY_MODES = ("starttls", "ssl", "none")
TIMEOUT = 10.0
MAX_DISCORD = 1900


class ChannelError(ValueError):
    """A channel setting that cannot be accepted; the message is shown to the user."""


class SendError(RuntimeError):
    """A message could not be delivered; the message is stored with the channel and shown to the user."""


Post = Callable[[str, bytes, dict, float], int]
SmtpFactory = Callable[[str, int, str, float], "smtplib.SMTP"]


def default_post(url: str, body: bytes, headers: dict, timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme is validated)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SendError(f"could not reach the server: {getattr(exc, 'reason', exc)}") from exc


def default_smtp(host: str, port: int, security: str, timeout: float) -> smtplib.SMTP:
    if security == "ssl":
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    return smtplib.SMTP(host, port, timeout=timeout)


# ---- validation ------------------------------------------------------------------------------------------------
def _url(value, schemes: tuple[str, ...]) -> str:
    value = str(value or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in schemes or not parsed.hostname:
        raise ChannelError("Enter a full address starting with " + " or ".join(f"{s}://" for s in schemes) + ".")
    return value


def _addresses(value) -> list[str]:
    items = value if isinstance(value, list) else str(value or "").replace(";", ",").split(",")
    out = [str(a).strip() for a in items if str(a).strip()]
    if not out or any("@" not in a or " " in a or "\n" in a or "\r" in a for a in out):
        raise ChannelError("Enter at least one valid email address.")
    return out


def validate_config(kind: str, config: dict, previous: dict | None = None) -> dict:
    """Return the cleaned config for a channel. Secrets left out (None or "") keep their previous value."""
    if kind not in KINDS:
        raise ChannelError(f"Channel type must be one of: {', '.join(KINDS)}.")
    config, previous = config or {}, previous or {}

    def keep(name: str):
        value = config.get(name)
        return previous.get(name, "") if value in (None, "") else value

    if kind == "webhook":
        return {"url": _url(keep("url"), ("http", "https")), "secret": str(keep("secret") or "")}
    if kind in ("slack", "discord"):
        return {"url": _url(keep("url"), ("https",))}
    host = str(config.get("host") or previous.get("host") or "").strip()
    if not host:
        raise ChannelError("Enter the mail server's address.")
    security = config.get("security", previous.get("security", "starttls"))
    if security not in SECURITY_MODES:
        raise ChannelError(f"Connection security must be one of: {', '.join(SECURITY_MODES)}.")
    try:
        port = int(config.get("port") or previous.get("port") or (465 if security == "ssl" else 587))
    except (TypeError, ValueError):
        raise ChannelError("The port must be a number.") from None
    if not 1 <= port <= 65535:
        raise ChannelError("The port must be between 1 and 65535.")
    sender = str(config.get("from_addr") or previous.get("from_addr") or "").strip()
    if "@" not in sender or "\n" in sender or "\r" in sender:
        raise ChannelError("Enter the address the emails are sent from.")
    return {"host": host, "port": port, "security": security,
            "username": str(config.get("username", previous.get("username", "")) or ""),
            "password": str(keep("password") or ""), "from_addr": sender,
            "to_addrs": _addresses(config.get("to_addrs", previous.get("to_addrs")))}


def public_config(kind: str, config: dict) -> dict:
    """The config as the API shows it: secrets are replaced by a hint that they are set."""
    if kind in ("webhook", "slack", "discord"):
        parsed = urlparse(config.get("url", ""))
        out = {"url_host": parsed.hostname or "", "has_url": bool(config.get("url"))}
        if kind == "webhook":
            out["has_secret"] = bool(config.get("secret"))
        return out
    return {"host": config.get("host"), "port": config.get("port"), "security": config.get("security"),
            "username": config.get("username"), "has_password": bool(config.get("password")),
            "from_addr": config.get("from_addr"), "to_addrs": config.get("to_addrs", [])}


# ---- sending ---------------------------------------------------------------------------------------------------
def _check_status(status: int) -> None:
    if not 200 <= status < 300:
        raise SendError(f"the server answered with status {status}")


def send_http(kind: str, config: dict, subject: str, text: str, data: dict, post: Post = default_post) -> None:
    if kind == "slack":
        body = {"text": f"*{subject}*\n{text}"}
    elif kind == "discord":
        body = {"content": f"**{subject}**\n{text}"[:MAX_DISCORD]}
    else:
        body = {"source": "horizon-events", "subject": subject, "text": text, **data}
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "HorizonEvents"}
    if kind == "webhook" and config.get("secret"):
        digest = hmac.new(config["secret"].encode("utf-8"), raw, hashlib.sha256).hexdigest()
        headers["X-Horizon-Signature"] = f"sha256={digest}"
    _check_status(post(config["url"], raw, headers, TIMEOUT))


def send_email(config: dict, subject: str, text: str, attachments: list[tuple[str, bytes, str]] | None = None,
               smtp_factory: SmtpFactory = default_smtp) -> None:
    msg = EmailMessage()
    msg["Subject"] = " ".join(subject.split())  # no line breaks in a header
    msg["From"], msg["To"] = config["from_addr"], ", ".join(config["to_addrs"])
    msg.set_content(text)
    for filename, content, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(content, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    try:
        with smtp_factory(config["host"], config["port"], config["security"], TIMEOUT) as smtp:
            if config["security"] == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if config.get("username"):
                smtp.login(config["username"], config.get("password", ""))
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        raise SendError(f"the mail server refused or could not be reached: {exc}") from exc
