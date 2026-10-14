"""The ways a notification leaves ATDR: a Windows notification on this machine, email, and a chat group.

Each is on only when its settings are complete, and says in words what is missing when they are not. A sender
either delivers the message or raises DeliveryError with words fit for the System panel: never the password, and
never the chat address, which is a secret of its own (whoever has it can post to the group). A sender that
delivered the message but has something to say about it returns that as words; such a message is not sent again.
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from atdr.app.core.config import PROJECT_ROOT, Settings
from atdr.app.core.desktop import has_desktop
from atdr.app.services.release_service import process_alive

WINDOWS, EMAIL, CHAT = "windows", "email", "chat"
CHANNELS = (WINDOWS, EMAIL, CHAT)
CHANNEL_NAMES = {WINDOWS: "Windows notification", EMAIL: "Email", CHAT: "Chat message"}
TOAST_SCRIPT = PROJECT_ROOT / "scripts" / "show_notification.ps1"
SEND_SECONDS = 20
# Where a part of ATDR that has no desktop leaves a Windows notification for the helper that has one
# (scripts/desktop_agent.ps1, in the session of whoever is signed in), and how long it waits to be told it was shown.
DESKTOP_QUEUE = PROJECT_ROOT / ".atdr_runtime" / "desktop-notifications"
DESKTOP_WAIT_SECONDS = 15.0
# The record the helper keeps of itself while it runs: with nobody signed in there is no helper.
DESKTOP_HELPER = PROJECT_ROOT / ".atdr_runtime" / "desktop.lock"
# With nobody signed in a Windows notification waits, and is looked at again this soon: it is shown about a minute
# after someone signs in, not at the next of the hourly tries a failed channel is given.
NOBODY_SIGNED_IN_LOOK_AGAIN = timedelta(minutes=1)
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

    `look_again` is set when nothing is wrong and the message only has to wait (nobody is signed in to see it):
    the next try comes after that long, every time, instead of later and later.
    """

    def __init__(self, words: str, *, again: bool = True, look_again: timedelta | None = None) -> None:
        super().__init__(words)
        self.again = again
        self.look_again = look_again


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


def helper_at_the_desktop(record: Path = DESKTOP_HELPER, *, alive: Callable[[int, str], bool] = process_alive) -> bool:
    """Whether ATDR's helper runs in somebody's sign-in session (scripts/desktop_agent.ps1)."""

    try:
        held = json.loads(record.read_text(encoding="utf-8-sig"))
        return bool(alive(int(held["pid"]), str(held["started_at"])))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def hand_to_desktop(
    settings: Settings,
    message: Message,
    *,
    queue: Path = DESKTOP_QUEUE,
    wait_seconds: float = DESKTOP_WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    helper: Callable[[], bool] = helper_at_the_desktop,
) -> None:
    """Leaves the notification for the helper at the desktop and waits until the helper says it was shown.

    The helper takes <id>.json by renaming it to <id>.showing and leaves <id>.shown or <id>.failed. When nobody is
    signed in there is no helper, and nothing is left: the notification waits where it is on record, and is shown
    about a minute after someone signs in. One that is a day old by then is not shown any more; the dashboard's
    bell has it.
    """

    if not helper():
        raise DeliveryError("nobody is signed in to Windows on this machine, so there is no desktop to show it on; it is shown when someone signs in",
                            look_again=NOBODY_SIGNED_IN_LOOK_AGAIN)
    name = uuid.uuid4().hex
    waiting, showing, shown, failed = (queue / f"{name}.{kind}" for kind in ("json", "showing", "shown", "failed"))
    try:
        queue.mkdir(parents=True, exist_ok=True)
        arriving = queue / f"{name}.arriving"
        arriving.write_text(json.dumps(toast_environment(settings, message)), encoding="utf-8")
        os.replace(arriving, waiting)
    except OSError as error:
        raise DeliveryError(f"the notification could not be left for the desktop ({error.__class__.__name__})") from error
    waited = 0.0
    while True:
        if shown.exists():
            shown.unlink(missing_ok=True)
            return
        if failed.exists():
            failed.unlink(missing_ok=True)
            raise DeliveryError("Windows did not show the notification")
        if waited >= wait_seconds:
            break
        sleep(0.5)
        waited += 0.5
    try:
        waiting.unlink()
    except FileNotFoundError:
        if showing.exists() or shown.exists():
            # Taken at the last moment: it is being shown. The helper clears away what nobody collects.
            return
        raise DeliveryError("Windows did not show the notification") from None
    except OSError as error:
        raise DeliveryError(f"the notification could not be taken back ({error.__class__.__name__})") from error
    raise DeliveryError("ATDR's helper at the desktop did not take the notification in time")


def send_windows(
    settings: Settings,
    message: Message,
    *,
    run: Callable[..., Any] = subprocess.run,
    desktop: Callable[[], bool] = has_desktop,
    hand_over: Callable[[Settings, Message], None] = hand_to_desktop,
) -> None:
    if not desktop():
        hand_over(settings, message)
        return
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
