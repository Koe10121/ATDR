"""The ways a notification leaves ATDR: email, a chat group, and a Windows notification.

Nothing here reaches a real mail server, a real chat group or the screen: email is sent to a mail server that
runs inside the test, chat messages to a web server that does, and the Windows notification's script is given
no words to show.
"""

from __future__ import annotations

import base64
import email
import json
import smtplib
import socketserver
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

from atdr.app.core.config import Settings
from atdr.app.services import notification_channels as channels
from atdr.app.services.notification_channels import (
    DeliveryError,
    Message,
    channel_problem,
    channels_on,
    chat_payload,
    describe_channels,
    email_recipients,
    send_chat,
    send_email,
    send_windows,
    toast_environment,
)

SECRET_ADDRESS = "https://chat.example.org/hook/secret-token"
MESSAGE = Message(title="2 new Critical alerts", body="#7 Critical: malware / C2, raised 10:01\n#8 Critical: port scan, raised 10:02",
                  link="/alerts")


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **{
        "ATDR_NOTIFY_WINDOWS": True,
        "ATDR_NOTIFY_EMAIL_TO": "soc@example.org, lead@example.org",
        "SMTP_HOST": "mail.example.org",
        "SMTP_PORT": 587,
        "SMTP_FROM_EMAIL": "atdr@example.org",
        "ATDR_NOTIFY_CHAT_WEBHOOK_URL": SECRET_ADDRESS,
        **overrides,
    })


def test_each_channel_says_what_is_missing_before_it_is_on(monkeypatch, tmp_path):
    ready = _settings()
    assert channel_problem(ready, "email") is None and channel_problem(ready, "chat") is None
    assert email_recipients(_settings(ATDR_NOTIFY_EMAIL_TO=" a@x.org;b@x.org  c@x.org,, ")) == ["a@x.org", "b@x.org", "c@x.org"]

    assert channel_problem(_settings(ATDR_NOTIFY_EMAIL_TO=""), "email") == "no address to send to (ATDR_NOTIFY_EMAIL_TO is empty)"
    assert channel_problem(_settings(ATDR_NOTIFY_EMAIL_TO="soc@example.org, not-an-address"), "email") == (
        "ATDR_NOTIFY_EMAIL_TO has 1 entry that is not an email address")
    assert channel_problem(_settings(ATDR_NOTIFY_EMAIL_TO="soc@, @example.org"), "email") == (
        "ATDR_NOTIFY_EMAIL_TO has 2 entries that are not an email address")
    assert channel_problem(_settings(SMTP_HOST=" "), "email") == "no mail server (SMTP_HOST is empty)"
    assert channel_problem(_settings(SMTP_FROM_EMAIL=""), "email") == "no sender address (SMTP_FROM_EMAIL is empty or not an email address)"
    assert channel_problem(_settings(SMTP_FROM_EMAIL="ATDR"), "email") == "no sender address (SMTP_FROM_EMAIL is empty or not an email address)"
    # A password is never sent where anyone on the network could read it.
    plain = {"SMTP_USERNAME": "atdr", "SMTP_PASSWORD": "hunter2", "SMTP_USE_TLS": False}
    assert channel_problem(_settings(**plain), "email") == "the mail account's password would travel unencrypted (SMTP_USE_TLS=false)"
    assert channel_problem(_settings(**plain, SMTP_PORT=465), "email") is None, "port 465 is encrypted from its first byte"
    assert channel_problem(_settings(**plain, SMTP_HOST="127.0.0.1"), "email") is None, "a relay on this machine"
    assert channel_problem(_settings(SMTP_USE_TLS=False), "email") is None, "no account, so no password to protect"
    # An account that is named but has no password would only be refused at every message.
    assert channel_problem(_settings(SMTP_USERNAME="atdr.alerts"), "email") == "the mail account has no password (SMTP_PASSWORD is empty)"
    assert channel_problem(_settings(SMTP_USERNAME="atdr.alerts", SMTP_PASSWORD="app-password"), "email") is None

    assert channel_problem(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=""), "chat") == "no chat address (ATDR_NOTIFY_CHAT_WEBHOOK_URL is empty)"
    assert channel_problem(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="discord"), "chat") == "ATDR_NOTIFY_CHAT_WEBHOOK_URL is not a web address"
    assert channel_problem(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="ftp://chat.example.org/x"), "chat") == "ATDR_NOTIFY_CHAT_WEBHOOK_URL is not a web address"
    assert channel_problem(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="http://chat.example.org/hook"), "chat") == "the chat address must start with https://"
    assert channel_problem(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="http://127.0.0.1:9/hook"), "chat") is None
    assert channel_problem(ready, "pager") == "ATDR has no such channel"

    script = tmp_path / "show_notification.ps1"
    script.write_text("exit 0", encoding="utf-8")
    monkeypatch.setattr(channels, "TOAST_SCRIPT", script)
    monkeypatch.setattr(channels.sys, "platform", "win32")
    assert channel_problem(ready, "windows") is None and channels_on(ready) == ["windows", "email", "chat"]
    assert channel_problem(_settings(ATDR_NOTIFY_WINDOWS=False), "windows") == "switched off (ATDR_NOTIFY_WINDOWS=false)"
    monkeypatch.setattr(channels, "TOAST_SCRIPT", tmp_path / "gone.ps1")
    assert channel_problem(ready, "windows") == "scripts\\show_notification.ps1 is missing"
    monkeypatch.setattr(channels.sys, "platform", "linux")
    assert channel_problem(ready, "windows") == "this machine does not run Windows"
    assert channels_on(_settings(ATDR_NOTIFY_EMAIL_TO="", ATDR_NOTIFY_CHAT_WEBHOOK_URL="")) == []

    described = describe_channels(ready)
    assert described["email"] == {"name": "Email", "on": True, "why_off": None, "to": 2, "server": "mail.example.org"}
    assert described["chat"] == {"name": "Chat message", "on": True, "why_off": None, "service": "chat.example.org"}
    assert described["windows"] == {"name": "Windows notification", "on": False, "why_off": "this machine does not run Windows"}
    assert "secret-token" not in json.dumps(described)
    assert describe_channels(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL="", SMTP_HOST=""))["chat"]["service"] is None


class _MailHandler(socketserver.StreamRequestHandler):
    """As much of a mail server as one message needs."""

    def handle(self) -> None:
        self.wfile.write(b"220 test.example ESMTP\r\n")
        sender, recipients = "", []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", "replace").strip()
            verb = command.upper()
            if verb.startswith(("EHLO", "HELO")):
                self.wfile.write(f"250-test.example\r\n250-AUTH {self.server.offers}\r\n250 8BITMIME\r\n".encode())  # type: ignore[attr-defined]
            elif verb.startswith("AUTH"):
                words = command.split()
                self.server.sign_ins.append(words[1].upper())  # type: ignore[attr-defined]
                if words[1].upper() == "PLAIN":
                    password = base64.b64decode(words[2]).decode().split("\0")[-1]
                else:
                    self.wfile.write(b"334 UGFzc3dvcmQ6\r\n")
                    password = base64.b64decode(self.rfile.readline().strip()).decode()
                if password == "app-password":
                    self.wfile.write(b"235 2.7.0 Accepted\r\n")
                else:
                    # As Gmail does: the refusal, and then the connection is closed.
                    self.wfile.write(b"535 5.7.8 Username and Password not accepted\r\n")
                    return
            elif verb.startswith("MAIL FROM:"):
                sender = command[10:].split()[0].strip("<>")
                self.wfile.write(b"250 ok\r\n")
            elif verb.startswith("RCPT TO:"):
                address = command[8:].strip().strip("<>")
                if address.startswith("refused"):
                    self.wfile.write(b"550 no such user\r\n")
                else:
                    recipients.append(address)
                    self.wfile.write(b"250 ok\r\n")
            elif verb == "DATA":
                self.wfile.write(b"354 end with a dot\r\n")
                lines = []
                while (data := self.rfile.readline()) not in (b".\r\n", b""):
                    lines.append(data)
                self.server.received.append((sender, recipients, b"".join(lines)))  # type: ignore[attr-defined]
                self.wfile.write(b"250 queued\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"502 not here\r\n")


@pytest.fixture()
def mail_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _MailHandler)
    server.daemon_threads = True
    server.received = []  # type: ignore[attr-defined]
    server.sign_ins = []  # type: ignore[attr-defined]
    server.offers = "LOGIN PLAIN"  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_an_email_goes_through_a_mail_server_as_it_would_through_a_real_one(mail_server):
    settings = _settings(SMTP_HOST="127.0.0.1", SMTP_PORT=mail_server.server_address[1], SMTP_USE_TLS=False)
    assert send_email(settings, MESSAGE) is None

    (sender, recipients, raw), = mail_server.received
    assert (sender, recipients) == ("atdr@example.org", ["soc@example.org", "lead@example.org"])
    mail = email.message_from_bytes(raw)
    assert (mail["From"], mail["To"], mail["Subject"]) == ("MFU ATDR <atdr@example.org>", "soc@example.org, lead@example.org",
                                                           "[ATDR] 2 new Critical alerts")
    assert mail["Auto-Submitted"] == "auto-generated" and mail["Message-ID"].endswith("@example.org>") and mail["Date"]
    assert mail.get_content_type() == "text/plain"
    assert mail.get_payload(decode=True).decode("utf-8").replace("\r\n", "\n").strip() == (
        "#7 Critical: malware / C2, raised 10:01\n#8 Critical: port scan, raised 10:02\n\n"
        "Open ATDR on the machine it runs on to see more.")
    assert "/alerts" not in raw.decode("utf-8"), "a link into the dashboard is no use outside the machine"

    # One address refused: the others get the message. It counts as delivered, with that said, and is not sent again.
    note = send_email(_settings(SMTP_HOST="127.0.0.1", SMTP_PORT=mail_server.server_address[1], SMTP_USE_TLS=False,
                                ATDR_NOTIFY_EMAIL_TO="soc@example.org, refused@example.org"), MESSAGE)
    assert note == "the mail server refused 1 of the addresses the message was for"
    assert mail_server.received[-1][1] == ["soc@example.org"] and len(mail_server.received) == 2
    with pytest.raises(DeliveryError, match="the mail server refused every address the message was for"):
        send_email(_settings(SMTP_HOST="127.0.0.1", SMTP_PORT=mail_server.server_address[1], SMTP_USE_TLS=False,
                             ATDR_NOTIFY_EMAIL_TO="refused@example.org"), MESSAGE)
    # The server asked for encryption it does not offer.
    with pytest.raises(DeliveryError, match="does not offer the encryption or the sign-in ATDR asked for"):
        send_email(_settings(SMTP_HOST="127.0.0.1", SMTP_PORT=mail_server.server_address[1], SMTP_USE_TLS=True), MESSAGE)
    # Nothing listens there.
    mail_server.shutdown()
    mail_server.server_close()
    with pytest.raises(DeliveryError, match=r"the mail server could not be reached \(\w+\)"):
        send_email(settings, MESSAGE)


def test_the_account_signs_in_once_and_a_refusal_is_said_to_be_one(mail_server):
    # Tried with a real Gmail account on 10 October 2026: Gmail answered the sign-in with 535 and closed the
    # connection. smtplib's own login then tried a second method on the closed connection and reported
    # "disconnected", so ATDR said the server "did not take the message" and would have tried again for a day.
    account = {"SMTP_HOST": "127.0.0.1", "SMTP_PORT": mail_server.server_address[1], "SMTP_USE_TLS": False, "SMTP_USERNAME": "atdr.alerts"}
    assert send_email(_settings(**account, SMTP_PASSWORD="app-password"), MESSAGE) is None
    assert mail_server.sign_ins == ["PLAIN"] and len(mail_server.received) == 1

    with pytest.raises(DeliveryError) as refused:
        send_email(_settings(**account, SMTP_PASSWORD="the account's own password"), MESSAGE)
    assert str(refused.value) == "the mail server refused the account's name or password"
    assert refused.value.again is False, "the same password would be refused the same way: not tried again by itself"
    assert mail_server.sign_ins == ["PLAIN", "PLAIN"], "one try, not one for every method the server offers"
    assert len(mail_server.received) == 1

    # A server that offers only the older method is signed in to with that; one that offers none ATDR knows is said so.
    mail_server.offers = "LOGIN"
    assert send_email(_settings(**account, SMTP_PASSWORD="app-password"), MESSAGE) is None
    assert mail_server.sign_ins[-1] == "LOGIN" and len(mail_server.received) == 2
    mail_server.offers = "XOAUTH2 OAUTHBEARER"
    with pytest.raises(DeliveryError, match="does not offer the encryption or the sign-in ATDR asked for") as unknown:
        send_email(_settings(**account, SMTP_PASSWORD="app-password"), MESSAGE)
    assert unknown.value.again is False and len(mail_server.sign_ins) == 3


class _Mail:
    """A mail server's client that only writes down what it is asked to do."""

    esmtp_features = {"auth": " LOGIN PLAIN XOAUTH2"}
    auth_plain = auth_login = auth_cram_md5 = staticmethod(lambda challenge=None: "")

    def __init__(self, calls: list, *, login_error: Exception | None = None) -> None:
        self.calls, self.login_error = calls, login_error
        self.user = self.password = None

    def ehlo_or_helo_if_needed(self) -> None:
        pass

    def __call__(self, host, port, **kwargs):
        self.calls.append(("connect", host, port, sorted(kwargs)))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        self.calls.append(("quit",))
        return False

    def starttls(self, **kwargs) -> None:
        self.calls.append(("starttls", sorted(kwargs)))

    def auth(self, method: str, _answer) -> None:
        self.calls.append(("sign in", method, self.user, self.password))
        if self.login_error is not None:
            raise self.login_error

    def send_message(self, mail) -> dict:
        self.calls.append(("send", mail["Subject"]))
        return {}


def test_the_connection_is_encrypted_before_the_password_is_given():
    account = {"SMTP_USERNAME": " atdr.alerts ", "SMTP_PASSWORD": "hunter2"}
    calls: list = []
    send_email(_settings(**account), MESSAGE, smtp=_Mail(calls), smtp_ssl=lambda *_a, **_k: pytest.fail("port 587 starts unencrypted"))
    assert calls == [("connect", "mail.example.org", 587, ["timeout"]), ("starttls", ["context"]),
                     ("sign in", "PLAIN", "atdr.alerts", "hunter2"), ("send", "[ATDR] 2 new Critical alerts"), ("quit",)]

    # Port 465 is encrypted from the first byte: no STARTTLS.
    calls.clear()
    send_email(_settings(**account, SMTP_PORT=465), MESSAGE, smtp_ssl=_Mail(calls), smtp=lambda *_a, **_k: pytest.fail("465 is not plain"))
    assert [call[0] for call in calls] == ["connect", "sign in", "send", "quit"] and calls[0][3] == ["context", "timeout"]

    # No account: nothing to sign in with. Encryption switched off for a relay on the machine: none asked for.
    calls.clear()
    send_email(_settings(), MESSAGE, smtp=_Mail(calls))
    assert [call[0] for call in calls] == ["connect", "starttls", "send", "quit"]
    calls.clear()
    send_email(_settings(SMTP_HOST="127.0.0.1", SMTP_USE_TLS=False), MESSAGE, smtp=_Mail(calls))
    assert [call[0] for call in calls] == ["connect", "send", "quit"]


@pytest.mark.parametrize(("error", "words", "again"), [
    (smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted: hunter2"),
     "the mail server refused the account's name or password", False),
    (smtplib.SMTPSenderRefused(550, b"not allowed to send as atdr@example.org with hunter2", "atdr@example.org"),
     "the mail server refused the sender address", False),
    (smtplib.SMTPServerDisconnected("Connection unexpectedly closed while sending hunter2"),
     "the mail server did not take the message (SMTPServerDisconnected)", True),
    (TimeoutError("timed out talking to mail.example.org as hunter2"), "the mail server could not be reached (TimeoutError)", True),
])
def test_a_mail_failure_is_said_in_words_that_never_hold_the_password(error, words, again):
    with pytest.raises(DeliveryError) as failure:
        send_email(_settings(SMTP_USERNAME="atdr.alerts", SMTP_PASSWORD="hunter2"), MESSAGE, smtp=_Mail([], login_error=error))
    assert str(failure.value) == words and "hunter2" not in str(failure.value)
    # What only a changed setting can end is not tried again; what may pass by itself is.
    assert failure.value.again is again


def test_gmail_refusing_an_accounts_own_password_is_told_with_what_gmail_takes():
    refusal = smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
    for host, hinted in (("smtp.gmail.com", True), ("SMTP.GoogleMail.com", True), ("gmail.com", True), ("mail.example.org", False),
                         ("smtp.notgmail.com", False), ("gmail.com.example.org", False)):
        with pytest.raises(DeliveryError) as failure:
            send_email(_settings(SMTP_HOST=host, SMTP_USERNAME="someone@example.org", SMTP_PASSWORD="hunter2"), MESSAGE,
                       smtp=_Mail([], login_error=refusal))
        said = str(failure.value)
        assert said.startswith("the mail server refused the account's name or password") and failure.value.again is False
        assert said.endswith("; Gmail takes an app password here, not the account's own password") is hinted, host


class _ChatHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (the name http.server asks for)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.posted.append((self.path, self.headers.get("Content-Type"), json.loads(body)))  # type: ignore[attr-defined]
        if self.path == "/hook/moved":
            self.send_response(302)
            self.send_header("Location", "/hook/ok")
        else:
            self.send_response({"/hook/ok": 204, "/hook/slow-down": 429, "/hook/broken": 503}.get(self.path, 404))
        self.end_headers()

    def log_message(self, *_args) -> None:
        pass


@pytest.fixture()
def chat_server():
    server = HTTPServer(("127.0.0.1", 0), _ChatHandler)
    server.posted = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_a_chat_message_is_posted_to_the_address_in_the_settings_and_nowhere_else(chat_server):
    base = f"http://127.0.0.1:{chat_server.server_address[1]}"
    send_chat(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=f"{base}/hook/ok"), MESSAGE)
    assert chat_server.posted == [("/hook/ok", "application/json", {
        "text": "ATDR: 2 new Critical alerts\n#7 Critical: malware / C2, raised 10:01\n#8 Critical: port scan, raised 10:02\n\n"
                "Open ATDR on the machine it runs on to see more."})]

    # An address that is gone will not come back by itself; a service that is busy or broken may.
    with pytest.raises(DeliveryError, match="^the chat service answered 404$") as gone:
        send_chat(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=f"{base}/hook/deleted"), MESSAGE)
    with pytest.raises(DeliveryError, match="^the chat service answered 429$") as busy:
        send_chat(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=f"{base}/hook/slow-down"), MESSAGE)
    with pytest.raises(DeliveryError, match="^the chat service answered 503$") as broken:
        send_chat(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=f"{base}/hook/broken"), MESSAGE)
    # Sent on to another address: the message is not posted there.
    with pytest.raises(DeliveryError, match="^the chat service answered 302$") as moved:
        send_chat(_settings(ATDR_NOTIFY_CHAT_WEBHOOK_URL=f"{base}/hook/moved"), MESSAGE)
    assert (gone.value.again, busy.value.again, broken.value.again, moved.value.again) == (False, True, True, False)
    assert [path for path, _type, _body in chat_server.posted] == ["/hook/ok", "/hook/deleted", "/hook/slow-down", "/hook/broken", "/hook/moved"]


def test_each_chat_service_gets_the_form_it_takes():
    text = "ATDR: New Critical alert #7: malware / C2\nRaised 10:01."
    assert chat_payload("https://hooks.slack.com/services/T0/B0/x", text) == {"text": text}
    assert chat_payload("https://chat.googleapis.com/v1/spaces/A/messages?key=k&token=t", text) == {"text": text}
    assert chat_payload("https://chat.example.org/hook", text) == {"text": text}
    for address in ("https://discord.com/api/webhooks/1/abc", "https://ptb.discord.com/api/webhooks/1/abc",
                    "https://discordapp.com/api/webhooks/1/abc"):
        assert chat_payload(address, text) == {"content": text, "allowed_mentions": {"parse": []}}, address
    assert chat_payload("https://notdiscord.com/api/webhooks/1/abc", text) == {"text": text}, "the service, not a name that ends like it"

    # Discord refuses more than 2,000 characters: the end is cut, and said to be.
    long = "\n".join(f"#{number} Critical: malware / C2, raised 10:01" for number in range(100))
    cut = chat_payload("https://discord.com/api/webhooks/1/abc", long)["content"]
    assert len(cut) <= 2000 and cut.endswith("\n...") and cut.startswith("#0 Critical")
    assert chat_payload("https://hooks.slack.com/services/T0/B0/x", long) == {"text": long}


def test_a_chat_failure_never_says_the_address():
    def unreachable(address, **_kwargs):
        raise requests.ConnectionError(f"HTTPSConnectionPool: Max retries exceeded with url: {address}")

    with pytest.raises(DeliveryError) as failure:
        send_chat(_settings(), MESSAGE, post=unreachable)
    assert str(failure.value) == "the chat service could not be reached (ConnectionError)"
    assert failure.value.__cause__ is None and failure.value.__suppress_context__, "nor does the error it came from travel with it"

    seen = {}

    def post(address, **kwargs):
        seen.update(address=address, **kwargs)
        return type("Answer", (), {"status_code": 200})()

    send_chat(_settings(), MESSAGE, post=post)
    assert (seen["address"], seen["allow_redirects"], seen["timeout"]) == (SECRET_ADDRESS, False, 20)


def test_a_windows_notification_gets_its_words_and_the_page_to_open(monkeypatch):
    settings = _settings(MFU_IAM_HANDOFF_FRONTEND_URL="http://127.0.0.1:5173/")
    assert toast_environment(settings, MESSAGE) == {
        "ATDR_NOTIFICATION_TITLE": "2 new Critical alerts",
        "ATDR_NOTIFICATION_BODY": "#7 Critical: malware / C2, raised 10:01\n#8 Critical: port scan, raised 10:02",
        "ATDR_NOTIFICATION_LINK": "http://127.0.0.1:5173/alerts",
    }
    many = Message(title="12 new Critical alerts", body="\n".join(f"#{number} Critical: port scan, raised 10:01" for number in range(11)) + "\nand 2 more")
    assert toast_environment(settings, many)["ATDR_NOTIFICATION_BODY"].splitlines() == [
        "#0 Critical: port scan, raised 10:01", "#1 Critical: port scan, raised 10:01", "#2 Critical: port scan, raised 10:01",
        "and 9 more lines"], "a Windows notification has room for four lines"
    assert toast_environment(settings, Message(title="Test", body=""))["ATDR_NOTIFICATION_LINK"] == ""

    ran = {}

    def run(command, **kwargs):
        ran.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, ran.get("answer", 0))

    send_windows(settings, MESSAGE, run=run)
    assert ran["command"][0] == "powershell.exe" and ran["command"][-2:] == ["-File", str(channels.TOAST_SCRIPT)]
    assert ran["env"]["ATDR_NOTIFICATION_TITLE"] == "2 new Critical alerts" and ran["env"]["ATDR_NOTIFICATION_LINK"].endswith("/alerts")
    assert "2 new Critical alerts" not in " ".join(ran["command"]), "the words are not on the command line, where they would need quoting"
    assert ran["timeout"] == 20

    ran["answer"] = 1
    with pytest.raises(DeliveryError, match=r"Windows did not show the notification \(the script ended with 1\)"):
        send_windows(settings, MESSAGE, run=run)

    def hangs(command, **_kwargs):
        raise subprocess.TimeoutExpired(command, 20)

    with pytest.raises(DeliveryError, match="Windows did not show the notification in time"):
        send_windows(settings, MESSAGE, run=hangs)

    def missing(_command, **_kwargs):
        raise FileNotFoundError("powershell.exe")

    with pytest.raises(DeliveryError, match=r"the notification script could not be run \(FileNotFoundError\)"):
        send_windows(settings, MESSAGE, run=missing)


def test_without_a_desktop_the_notification_is_handed_to_the_helper_that_has_one(tmp_path):
    # Started with the machine (scripts\autostart.cmd -BeforeSignIn), ATDR's parts have no desktop: a notification
    # they showed themselves would be shown to nobody, and Windows would say that it went well.
    settings = _settings(MFU_IAM_HANDOFF_FRONTEND_URL="http://127.0.0.1:5173/")
    handed, ran = [], []

    def shown_from_here(command, **_kwargs):
        ran.append(command)
        return subprocess.CompletedProcess(command, 0)

    send_windows(settings, MESSAGE, run=shown_from_here, desktop=lambda: False, hand_over=lambda given, message: handed.append((given, message)))
    assert handed == [(settings, MESSAGE)] and ran == []
    send_windows(settings, MESSAGE, run=shown_from_here, desktop=lambda: True, hand_over=lambda given, message: handed.append((given, message)))
    assert len(handed) == 1 and len(ran) == 1, "at a desktop it is shown from here, as it always was"

    queue = tmp_path / "desktop-notifications"
    seen = []

    def a_helper_that_answers(answer: str):
        def between_two_looks(_seconds: float) -> None:
            # What scripts\desktop_agent.ps1 does with a file: takes it by renaming it, and leaves how it went.
            for waiting in queue.glob("*.json"):
                seen.append(json.loads(waiting.read_text(encoding="utf-8")))
                waiting.replace(waiting.with_suffix(".showing"))
                waiting.with_suffix(".showing").replace(waiting.with_suffix(f".{answer}"))
        return between_two_looks

    channels.hand_to_desktop(settings, MESSAGE, queue=queue, sleep=a_helper_that_answers("shown"), helper=lambda: True)
    assert seen == [toast_environment(settings, MESSAGE)], "the same words, in the form the script that shows them takes"
    assert list(queue.iterdir()) == [], "the answer is collected, and nothing is left half written"

    with pytest.raises(DeliveryError, match="^Windows did not show the notification$") as refused:
        channels.hand_to_desktop(settings, MESSAGE, queue=queue, sleep=a_helper_that_answers("failed"), helper=lambda: True)
    assert (refused.value.again, refused.value.look_again) == (True, None) and list(queue.iterdir()) == []


def test_with_nobody_signed_in_the_notification_waits_and_nothing_is_left_lying(tmp_path):
    settings = _settings()
    queue = tmp_path / "desktop-notifications"
    slept: list[float] = []
    with pytest.raises(DeliveryError, match="^nobody is signed in to Windows on this machine, .* it is shown when someone signs in$") as waits:
        channels.hand_to_desktop(settings, MESSAGE, queue=queue, sleep=slept.append, helper=lambda: False)
    assert waits.value.again is True and waits.value.look_again == channels.NOBODY_SIGNED_IN_LOOK_AGAIN
    assert channels.NOBODY_SIGNED_IN_LOOK_AGAIN.total_seconds() == 60
    assert slept == [] and not queue.exists(), "not waited for, and nothing written: there is nobody to take it"

    # A helper that is there and takes nothing (the user is signing out): the file is taken back, so that it is
    # not shown a second time when the notification is tried again.
    with pytest.raises(DeliveryError, match="^ATDR's helper at the desktop did not take the notification in time$") as late:
        channels.hand_to_desktop(settings, MESSAGE, queue=queue, wait_seconds=3, sleep=slept.append, helper=lambda: True)
    assert late.value.look_again is None and sum(slept) == 3 and list(queue.iterdir()) == []
    assert channels.DESKTOP_WAIT_SECONDS == 15

    # Taken at the last moment: it is being shown, and is not reported as lost.
    looks: list[float] = []

    def taken_at_the_last_moment(seconds: float) -> None:
        looks.append(seconds)
        if len(looks) == 2:
            for waiting in queue.glob("*.json"):
                waiting.replace(waiting.with_suffix(".showing"))

    channels.hand_to_desktop(settings, MESSAGE, queue=queue, wait_seconds=1, sleep=taken_at_the_last_moment, helper=lambda: True)
    assert [path.suffix for path in queue.iterdir()] == [".showing"]

    # A folder that cannot be written to is said, not raised as it is.
    (tmp_path / "a file").write_text("", encoding="utf-8")
    with pytest.raises(DeliveryError, match=r"^the notification could not be left for the desktop \((FileExistsError|NotADirectoryError)\)$"):
        channels.hand_to_desktop(settings, MESSAGE, queue=tmp_path / "a file", sleep=slept.append, helper=lambda: True)


def test_the_helper_is_there_while_the_process_it_wrote_down_runs(tmp_path):
    record = tmp_path / "desktop.lock"
    asked = []

    def alive(pid: int, started_at: str) -> bool:
        asked.append((pid, started_at))
        return True

    assert channels.helper_at_the_desktop(record, alive=alive) is False and asked == [], "no record: no helper was ever started"
    # As PowerShell writes it: with a mark at the start of the file, and seven decimals of a second.
    record.write_text('﻿{"pid": 4321, "started_at": "2026-10-11T07:00:00.1234567Z"}', encoding="utf-8")
    assert channels.helper_at_the_desktop(record, alive=alive) is True and asked == [(4321, "2026-10-11T07:00:00.1234567Z")]
    assert channels.helper_at_the_desktop(record, alive=lambda _pid, _started: False) is False, "its record outlives a helper that was ended"
    for unusable in ("{ not json", '{"pid": "x", "started_at": ""}', "[]", '{"started_at": "2026-10-11T07:00:00Z"}'):
        record.write_text(unusable, encoding="utf-8")
        assert channels.helper_at_the_desktop(record, alive=alive) is False, unusable
    assert channels.DESKTOP_HELPER == Path(channels.PROJECT_ROOT) / ".atdr_runtime" / "desktop.lock"
    assert channels.DESKTOP_QUEUE == Path(channels.PROJECT_ROOT) / ".atdr_runtime" / "desktop-notifications"


def test_the_notification_script_shows_nothing_without_a_title(tmp_path):
    # Run for real, with no words: it must end before it reaches the screen.
    assert channels.TOAST_SCRIPT == Path(channels.PROJECT_ROOT) / "scripts" / "show_notification.ps1" and channels.TOAST_SCRIPT.is_file()
    done = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(channels.TOAST_SCRIPT)],
        capture_output=True, text=True, timeout=120, check=False, cwd=tmp_path,
        env={key: value for key, value in __import__("os").environ.items() if not key.startswith("ATDR_NOTIFICATION_")},
    )
    assert done.returncode == 2, done.stderr or done.stdout
