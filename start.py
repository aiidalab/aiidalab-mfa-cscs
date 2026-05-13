import asyncio
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

import humanize
import ipywidgets as ipw
import requests

__version__ = "v2023.1003"

# Endpoints — mirror src/config.rs in eth-cscs/cscs-key. Re-sync if CSCS
# changes the gateway paths.
ISSUER_URL = "https://auth.cscs.ch/auth/realms/cscs"
SIGN_URL = "https://authx-gateway.svc.cscs.ch/api-ssh-service/api/v1/ssh-keys/sign"
SA_TOKEN_URL = "https://authx-gateway.svc.cscs.ch/api-service-account/api/v1/auth/token"
PKCE_CLIENT_ID = "authx-cli"
DEFAULT_HEADERS = {"X-Client-Type": "cli"}


class CscsError(Exception):
    """Raised on any auth/signing failure surfaced to the user."""


class HeaderWarning(ipw.HTML):
    """Class to display a warning in the header."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.layout = ipw.Layout(display="none", width="600px")

    def show(self, message, danger_level="alert-danger"):
        self.value = (
            f"""<div class="alert {danger_level}" role="alert">{message}</div>"""
        )
        self.layout.display = "block"

    def hide(self):
        self.layout.display = "none"


def discover_oidc():
    """Fetch device_authorization_endpoint and token_endpoint from the issuer."""
    resp = requests.get(
        f"{ISSUER_URL}/.well-known/openid-configuration",
        headers=DEFAULT_HEADERS,
        timeout=10,
    )
    resp.raise_for_status()
    doc = resp.json()
    return doc["device_authorization_endpoint"], doc["token_endpoint"]


def request_device_code(device_endpoint):
    resp = requests.post(
        device_endpoint,
        data={"client_id": PKCE_CLIENT_ID, "scope": "openid"},
        headers=DEFAULT_HEADERS,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def poll_for_token(token_endpoint, device_code, interval, deadline):
    """Poll token endpoint until the user authorizes or the code expires."""
    interval = max(interval, 1)
    while time.monotonic() < deadline:
        resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": PKCE_CLIENT_ID,
            },
            headers=DEFAULT_HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()["access_token"]
        err = resp.json().get("error")
        if err == "authorization_pending":
            pass
        elif err == "slow_down":
            interval += 5
        elif err == "expired_token":
            raise CscsError("Device code expired before login completed.")
        else:
            raise CscsError(f"Token endpoint returned: {err or resp.text}")
        time.sleep(interval)
    raise CscsError("Timed out waiting for device authorization.")


def token_from_api_key(api_key):
    resp = requests.post(
        SA_TOKEN_URL,
        headers={**DEFAULT_HEADERS, "X-API-Key": api_key},
        timeout=10,
    )
    if resp.status_code != 200:
        raise CscsError(f"API-key auth failed: {resp.status_code} {resp.text}")
    return resp.json()["access_token"]


def sign_public_key(access_token, public_key_text, duration="1d"):
    resp = requests.post(
        SIGN_URL,
        json={"publicKey": public_key_text, "duration": duration},
        headers={
            **DEFAULT_HEADERS,
            "Authorization": f"Bearer {access_token}",
        },
        timeout=15,
    )
    if not resp.ok:
        try:
            msg = resp.json().get("message", resp.text)
        except ValueError:
            msg = resp.text
        raise CscsError(f"Signing failed: {msg}")
    return resp.json()["sshKey"]["publicKey"]


def ensure_keypair(private_key_file):
    """Generate ~/.ssh/cscs-key if it doesn't exist. Returns public key text."""
    private_key_file.parent.mkdir(mode=0o700, exist_ok=True)
    pub_file = private_key_file.with_suffix(".pub")
    if not private_key_file.exists() or not pub_file.exists():
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(private_key_file),
                "-N",
                "",
                "-C",
                "cscs-key",
            ],
            check=True,
            capture_output=True,
        )
    return pub_file.read_text()


def add_proxy_server_to_known_hosts():
    output = subprocess.run(
        ["ssh-keyscan", "ela.cscs.ch"],
        encoding="utf-8",
        check=True,
        capture_output=True,
    ).stdout
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    known_hosts.touch(exist_ok=True)
    existing = known_hosts.read_text()
    if output not in existing:
        with open(known_hosts, "a") as fh:
            fh.write(output)


class MfaAuthenicathionWidget(ipw.VBox):
    """Widget to fetch a CSCS-signed SSH certificate via OIDC device flow or API key."""

    key_warning_threshold = 8  # hours

    def __init__(self):
        self.private_key_file = Path.home() / ".ssh" / "cscs-key"
        self.public_key_file = Path.home() / ".ssh" / "cscs-key.pub"
        self.cert_file = Path.home() / ".ssh" / "cscs-key-cert.pub"

        self.method = ipw.ToggleButtons(
            options=[("Device login (browser)", "device"), ("API key", "apikey")],
            value="device",
            description="Auth:",
            layout=ipw.Layout(width="800px", justify_content="space-around"),
            style={"button_width": "200px"},
        )
        self.api_key = ipw.Password(description="API key:")
        self.api_key.layout.display = "none"
        self.api_key_help = ipw.HTML(
            value=(
                '<div class="alert alert-info">'
                "<b>For automation only (CI/CD pipelines, scheduled scripts).</b> "
                "API keys belong to a <em>service account</em>, not a personal account. "
                "To create one, go to your project on "
                '<a href="https://portal.cscs.ch/projects/" target="_blank">portal.cscs.ch</a>, '
                "select the <b>Project</b>, open the <b>Team</b> tab, and add a service account. "
                "The API key is shown only once at creation — store it securely. "
                "For interactive use, choose <b>Device login</b> instead."
                "</div>"
            ),
        )
        self.api_key_help.layout.display = "none"
        self.method.observe(self._on_method_change, names="value")

        self.go_button = ipw.Button(
            description="Update the key", button_style="primary"
        )
        self.go_button.on_click(self._on_go)

        self.device_info = ipw.HTML()
        self.output = ipw.HTML()
        self.key_validity_info = HeaderWarning()

        super().__init__(
            children=[
                self.key_validity_info,
                self.method,
                self.api_key,
                self.api_key_help,
                self.go_button,
                self.device_info,
                self.output,
            ]
        )
        asyncio.ensure_future(self._start_periodic_refresh(5))
        self.refresh_info()

    def _on_method_change(self, change):
        visible = "" if change["new"] == "apikey" else "none"
        self.api_key.layout.display = visible
        self.api_key_help.layout.display = visible

    def _on_go(self, _):
        self.output.value = ""
        self.device_info.value = ""
        self.go_button.disabled = True
        asyncio.ensure_future(self._run())

    async def _run(self):
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._do_update)
        except CscsError as exc:
            self._error(str(exc))
        except subprocess.CalledProcessError as exc:
            self._error(
                f"Local command failed: {exc.stderr.decode() if exc.stderr else exc}"
            )
        except requests.RequestException as exc:
            self._error(f"Network error: {exc}")
        finally:
            self.go_button.disabled = False
            self.device_info.value = ""

    def _do_update(self):
        self._info("Preparing keypair…")
        public_key = ensure_keypair(self.private_key_file)

        if self.method.value == "apikey":
            if not self.api_key.value:
                raise CscsError("API key is required.")
            self._info("Exchanging API key for access token…")
            access_token = token_from_api_key(self.api_key.value)
        else:
            self._info("Discovering OIDC endpoints…")
            device_endpoint, token_endpoint = discover_oidc()
            self._info("Requesting device code…")
            dc = request_device_code(device_endpoint)
            uri = dc.get("verification_uri_complete") or dc["verification_uri"]
            self.device_info.value = (
                f'<div class="alert alert-info">'
                f"Open <a href='{uri}' target='_blank'>{uri}</a>. Waiting for login…</div>"
            )
            deadline = time.monotonic() + int(dc.get("expires_in", 600))
            access_token = poll_for_token(
                token_endpoint, dc["device_code"], int(dc.get("interval", 5)), deadline
            )

        self._info("Signing public key…")
        cert = sign_public_key(access_token, public_key)
        self.cert_file.write_text(cert)
        os.chmod(self.cert_file, 0o644)

        subprocess.run(
            ["ssh-add", "-t", "1d", str(self.private_key_file)],
            check=True,
            encoding="utf-8",
        )
        add_proxy_server_to_known_hosts()
        self.output.value = (
            '<div class="alert alert-success">The keys were updated 👍</div>'
        )
        time.sleep(3)
        self.output.value = ""

    def _info(self, msg):
        self.output.value = f'<div class="alert alert-info">{msg}</div>'

    def _error(self, msg):
        self.output.value = f'<div class="alert alert-danger">{msg}</div>'

    # --- validity display ---------------------------------------------------

    def _parse_validity_time(self):
        output = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(self.cert_file)],
            encoding="utf-8",
            capture_output=True,
        ).stdout
        matched = (
            re.search(r"^.*Valid:.*$", output, flags=re.MULTILINE).group(0).split()
        )
        return datetime.fromisoformat(matched[2]), datetime.fromisoformat(matched[4])

    def time_left(self):
        _, end = self._parse_validity_time()
        return end - datetime.now()

    def key_is_valid(self):
        start, end = self._parse_validity_time()
        return start < datetime.now() < end

    def cert_exists(self):
        return self.cert_file.exists() and self.private_key_file.exists()

    async def _start_periodic_refresh(self, period=5):
        while True:
            try:
                self.refresh_info()
            except Exception:
                pass
            await asyncio.sleep(period)

    def refresh_info(self):
        if not self.cert_exists():
            self.key_validity_info.show(
                "🚫 No CSCS SSH certificate found.", danger_level="alert-danger"
            )
            return
        if self.key_is_valid():
            left = humanize.naturaldelta(self.time_left())
            if self.time_left() < timedelta(hours=self.key_warning_threshold):
                self.key_validity_info.show(
                    f"⚠️ The SSH key expires in {left}.", danger_level="alert-warning"
                )
            else:
                self.key_validity_info.show(
                    f"👍 The SSH key is valid and expires in {left}.",
                    danger_level="alert-success",
                )
        else:
            self.key_validity_info.show(
                "🛑 The SSH key has expired.", danger_level="alert-danger"
            )


def get_start_widget(appbase, jupbase, notebase):
    return MfaAuthenicathionWidget()
