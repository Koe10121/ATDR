"""The ways a notification leaves ATDR: a Windows notification on this machine, email, and a chat group.

Each is on only when its settings are complete, and says in words what is missing when they are not. A sender
either delivers the message or raises DeliveryError with words fit for the System panel: never the password, and
never the chat address, which is a secret of its own (whoever has it can post to the group). A sender that
delivered the message but has something to say about it returns that as words; such a message is not sent again.
"""

from __future__ import annotations

import os
import re
import smtplib
import ssl
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from atdr.app.core.config import PROJECT_ROOT, Settings

WINDOWS, EMAIL, CHAT = "windows", "email", "chat"
CHANNELS = (WINDOWS, EMAIL, CHAT)
CHANNEL_NAMES = {WINDOWS: "Windows notification", EMAIL: "Email", CHAT: "Chat message"}
TOAST_SCRIPT = PROJECT_ROOT / "scripts" / "show_notification.ps1"
SEND_SECONDS = 20
# What a Windows notification shows of the body before it cuts it off.
TOAST_LINES = 4
# Discord refuses a message longer than this.
DISCORD_LIMIT = 2000
ADDRESS = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
FOOTER = "Open ATDR on the machine it runs on to see more."


class DeliveryError(Exception):
    """A message that was not delivered, with why in words that may be shown.

    `again` is False when another try cannot help until someone changes a setting: a sign-in the mail server
    refused, a sender or addresses it will not take, a chat address that is gone. Such a message is not sent
    again by itself; each try would be one more refused sign-in on the account.
    """

    def __init__(self, words: str, *, again: bool = True) -> None:
        super().__init__(words)
        self.again = again


@dataclass(frozen=True)
class Message:
    title: str
    body: str
    # A page of the dashboard, such as /alerts?alert=4163.
    link: str | None = None


def email_recipients(settings: Settings) -> list[str]:
    return [address.strip() for address in re.split(r"[,;\s]+", settings.notify_email_to) if address.strip()]


def channel_problem(settings: Settings, channel: str) -> str | None:
    """Why the channel is off, in words; None when it is set up."""

    if channel == WINDOWS:
        if not settings.notify_windows:
            return "switched off (ATDR_NOTIFY_WINDOWS=false)"
        if sys.platform != "win32":
            return "this machine does not run Windows"
        return None if TOAST_SCRIPT.is_file() else "scripts\\show_notification.ps1 is missing"
    if channel == EMAIL:
        recipients = email_recipients(settings)
        if not recipients:
            return "no address to send to (ATDR_NOTIFY_EMAIL_TO is empty)"
        wrong = [address for address in recipients if ADDRESS.match(address) is None]
        if wrong:
            return f"ATDR_NOTIFY_EMAIL_TO has {len(wrong)} entr{'y' if len(wrong) == 1 else 'ies'} that {'is' if len(wrong) == 1 else 'are'} not an email address"
        if not settings.smtp_host.strip():
            return "no mail server (SMTP_HOST is empty)"
        if ADDRESS.match(settings.smtp_from_email.strip()) is None:
            return "no sender address (SMTP_FROM_EMAIL is empty or not an email address)"
        if settings.smtp_username.strip() and not settings.smtp_password:
            return "the mail account has no password (SMTP_PASSWORD is empty)"
        if settings.smtp_username.strip() and not _encrypted(settings) and settings.smtp_host.strip().lower() not in LOOPBACK_HOSTS:
            return "the mail account's password would travel unencrypted (SMTP_USE_TLS=false)"
        return None
    if channel == CHAT:
        address = settings.notify_chat_webhook_url.strip()
        if not address:
            return "no chat address (ATDR_NOTIFY_CHAT_WEBHOOK_URL is empty)"
        parsed = urlparse(address)
        if not parsed.hostname or parsed.scheme not in ("https", "http"):
            return "ATDR_NOTIFY_CHAT_WEBHOOK_URL is not a web address"
        if parsed.scheme != "https" and parsed.hostname.lower() not in LOOPBACK_HOSTS:
            return "the chat address must start with https://"
        return None
    return "ATDR has no such channel"


def channels_on(settings: Settings) -> list[str]:
    return [channel for channel in CHANNELS if channel_problem(settings, channel) is None]


def describe_channels(settings: Settings) -> dict[str, dict[str, Any]]:
    """What the System panel shows of each channel. Of the chat address only the service it belongs to."""

    described: dict[str, dict[str, Any]] = {}
    for channel in CHANNELS:
        problem = channel_problem(settings, channel)
        described[channel] = {"name": CHANNEL_NAMES[channel], "on": problem is None, "why_off": problem}
    described[EMAIL]["to"] = len(email_recipients(settings))
    described[EMAIL]["server"] = settings.smtp_host.strip() or None
    described[CHAT]["service"] = urlparse(settings.notify_chat_webhook_url.strip()).hostname if settings.notify_chat_webhook_url.strip() else None
    return described


def outward_text(message: Message) -> str:
    """The words of an email or a chat message. They cannot be clicked from outside, so the link is not sent."""

    body = message.body.strip()
    return f"{body}\n\n{FOOTER}" if body else FOOTER


def _encrypted(settings: Settings) -> bool:
    return int(settings.smtp_port) == 465 or bool(settings.smtp_use_tls)


# The sign-in methods ATDR can use, in smtplib's own order of preference.
SIGN_IN_METHODS = ("CRAM-MD5", "PLAIN", "LOGIN")
GOOGLE_MAIL = ("gmail.com", "googlemail.com")


def _sign_in(client: Any, name: str, password: str) -> None:
    """Signs in once, with the first method the server offers that ATDR knows.

    smtplib's own login tries every method in turn with the same password. A refusal is a refusal: the next try
    is only one more failed sign-in on the account, and Gmail has closed the connection by then, so what came
    back was "disconnected" where the truth was "refused".
    """

    client.ehlo_or_helo_if_needed()
    offered = str(client.esmtp_features.get("auth", "")).upper().split()
    for method in SIGN_IN_METHODS:
        if method in offered:
            client.user, client.password = name, password
            client.auth(method, getattr(client, "auth_" + method.lower().replace("-", "_")))
            return
    raise smtplib.SMTPNotSupportedError("the server offers no sign-in method that ATDR knows")


def _refused_sign_in(host: str) -> str:
    words = "the mail server refused the account's name or password"
    if any(host.lower() == name or host.lower().endswith("." + name) for name in GOOGLE_MAIL):
        # Google lets a mail program in with an app password only.
        words += "; Gmail takes an app password here, not the account's own password"
    return words


def send_email(
    settings: Settings,
    message: Message,
    *,
    smtp: Callable[..., Any] = smtplib.SMTP,
    smtp_ssl: Callable[..., Any] = smtplib.SMTP_SSL,
) -> str | None:
    host, port = settings.smtp_host.strip(), int(settings.smtp_port)
    sender = settings.smtp_from_email.strip()
    mail = EmailMessage()
    mail["From"] = f"MFU ATDR <{sender}>"
    mail["To"] = ", ".join(email_recipients(settings))
    mail["Subject"] = f"[ATDR] {message.title}"
    mail["Date"] = formatdate(localtime=True)
    mail["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
    # A mail program must not answer this with an out-of-office reply.
    mail["Auto-Submitted"] = "auto-generated"
    mail.set_content(outward_text(message))
    try:
        if port == 465:
            client = smtp_ssl(host, port, timeout=SEND_SECONDS, context=ssl.create_default_context())
        else:
            client = smtp(host, port, timeout=SEND_SECONDS)
        with client:
            if port != 465 and settings.smtp_use_tls:
                client.starttls(context=ssl.create_default_context())
            if settings.smtp_username.strip():
                _sign_in(client, settings.smtp_username.strip(), settings.smtp_password)
            refused = client.send_message(mail)
    # The first four need a setting put right: the same message would be refused the same way again.
    except smtplib.SMTPAuthenticationError as error:
        raise DeliveryError(_refused_sign_in(host), again=False) from error
    except smtplib.SMTPRecipientsRefused as error:
        raise DeliveryError("the mail server refused every address the message was for", again=False) from error
    except smtplib.SMTPSenderRefused as error:
        raise DeliveryError("the mail server refused the sender address", again=False) from error
    except smtplib.SMTPNotSupportedError as error:
        raise DeliveryError("the mail server does not offer the encryption or the sign-in ATDR asked for", again=False) from error
    except ssl.SSLError as error:
        raise DeliveryError("the encrypted connection to the mail server could not be set up") from error
    except smtplib.SMTPException as error:
        raise DeliveryError(f"the mail server did not take the message ({error.__class__.__name__})") from error
    except OSError as error:
        raise DeliveryError(f"the mail server could not be reached ({error.__class__.__name__})") from error
    if refused:
        # The other addresses have it: sending it again would only send it to them twice.
        return f"the mail server refused {len(refused)} of the addresses the message was for"
    return None


def chat_payload(address: str, text: str) -> dict[str, Any]:
    """What the chat service expects. Discord names the text "content"; Slack, Google Chat and most others "text"."""

    host = (urlparse(address).hostname or "").lower()
    if host == "discord.com" or host.endswith(".discord.com") or host == "discordapp.com" or host.endswith(".discordapp.com"):
        if len(text) > DISCORD_LIMIT:
            text = text[: DISCORD_LIMIT - 4].rstrip() + "\n..."
        # Nothing ATDR writes may notify everyone in the group, whatever words it holds.
        return {"content": text, "allowed_mentions": {"parse": []}}
    return {"text": text}


def send_chat(settings: Settings, message: Message, *, post: Callable[..., Any] = requests.post) -> None:
    address = settings.notify_chat_webhook_url.strip()
    text = f"ATDR: {message.title}\n{outward_text(message)}"
    try:
        # Not followed elsewhere: the message goes to the address in the settings or nowhere.
        answer = post(address, json=chat_payload(address, text), timeout=SEND_SECONDS, allow_redirects=False)
    except requests.RequestException as error:
        # Not the error's own words: they can hold the address.
        raise DeliveryError(f"the chat service could not be reached ({error.__class__.__name__})") from None
    code = int(answer.status_code)
    if not 200 <= code < 300:
        # Busy or broken for now is worth another try; "no such address" or "not allowed" is not.
        raise DeliveryError(f"the chat service answered {code}", again=code in (408, 425, 429) or code >= 500)


def toast_environment(settings: Settings, message: Message) -> dict[str, str]:
    """The notification's words for scripts/show_notification.ps1, as environment variables: nothing to quote."""

    lines = [line for line in message.body.splitlines() if line.strip()]
    if len(lines) > TOAST_LINES:
        lines = [*lines[: TOAST_LINES - 1], f"and {len(lines) - TOAST_LINES + 1} more lines"]
    link = f"{settings.mfu_iam_handoff_frontend_url.rstrip('/')}{message.link}" if message.link else ""
    return {"ATDR_NOTIFICATION_TITLE": message.title, "ATDR_NOTIFICATION_BODY": "\n".join(lines), "ATDR_NOTIFICATION_LINK": link}


def send_windows(settings: Settings, message: Message, *, run: Callable[..., Any] = subprocess.run) -> None:
    try:
        done = run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(TOAST_SCRIPT)],
            env={**os.environ, **toast_environment(settings, message)},
            capture_output=True, text=True, timeout=SEND_SECONDS,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as error:
        raise DeliveryError("Windows did not show the notification in time") from error
    except OSError as error:
        raise DeliveryError(f"the notification script could not be run ({error.__class__.__name__})") from error
    if done.returncode != 0:
        raise DeliveryError(f"Windows did not show the notification (the script ended with {done.returncode})")


Sender = Callable[[Settings, Message], str | None]
SENDERS: dict[str, Sender] = {WINDOWS: send_windows, EMAIL: send_email, CHAT: send_chat}
