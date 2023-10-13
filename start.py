import asyncio
import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import humanize
import ipywidgets as ipw
import requests


class UnableToFetchKeyError(Exception):
    """Exception raised when unable to fetch the key."""

    def __init__(self, key_type):
        super().__init__(f"Unable to fetch {key_type} key.")


class InputNotProvidedError(Exception):
    """Exception raised when a certain input is not provided."""

    def __init__(self, input_type):
        super().__init__(f"{input_type} is not provided.")


class HeaderWarning(ipw.HTML):
    """Class to display a warning in the header."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.layout = ipw.Layout(
            display="none",
            width="600px",
            height="auto",
            margin="0px 0px 0px 0px",
            padding="0px 0px 0px 0px",
        )

    def show(self, message, danger_level="alert-danger"):
        """Show the warning."""
        self.value = (
            f"""<div class="alert {danger_level}" role="alert">{message}</div>"""
        )
        self.layout.display = "block"

    def hide(self):
        """Hide the warning."""
        self.layout.display = "none"


class MfaAuthenicathionWidget(ipw.VBox):
    """MFA Authentication Widget."""

    api_get_keys = "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key"
    key_warning_threshold = 8  # hours

    def __init__(self):
        self.username = ipw.Text(description="Username:", disabled=False)
        self.password = ipw.Password(description="Password:", disabled=False)
        self.otp = ipw.Text(description="OTP:", disabled=False)

        self.private_key_file = Path.home() / ".ssh" / "cscs-key"
        self.public_key_file = Path.home() / ".ssh" / "cscs-key-cert.pub"

        setup_button = ipw.Button(description="Update the key")
        setup_button.on_click(self.setup)

        self.key_validity_info = HeaderWarning()
        self.output = ipw.HTML()
        super().__init__(
            children=[
                self.key_validity_info,
                ipw.HBox(
                    [
                        self.username,
                        self.password,
                        self.otp,
                    ]
                ),
                setup_button,
                self.output,
            ]
        )
        asyncio.ensure_future(self._start_periodic_refresh(5))
        self.refresh_info()

    def setup(self, _=None):
        self.output.value = "Trying to get the keys..."
        try:
            keys = self.get_keys()
        except InputNotProvidedError as exc:
            self.output.value = (
                f"""<div class="alert alert-danger" role="alert">{str(exc)}</div>"""
            )
            return
        self.store_the_keys(*keys)

        # Add the key to the ssh-agent.
        self.add_key_to_ssh_agent()

        self.output.value = "The keys were updated 👍"

    def add_key_to_ssh_agent(self):
        """Add the key to the ssh-agent."""
        subprocess.run(
            ["ssh-add", "-t", "1d", str(self.private_key_file)],
            encoding="utf-8",
            check=True,
        )

    def get_keys(self):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if not self.username.value:
            raise InputNotProvidedError("Username")
        if not self.password.value:
            raise InputNotProvidedError("Password")
        if not self.otp.value:
            raise InputNotProvidedError("OTP")

        auth_data = {
            "username": self.username.value,
            "password": self.password.value,
            "otp": self.otp.value,
        }
        try:
            resp = requests.post(
                self.api_get_keys,
                data=json.dumps(auth_data),
                headers=headers,
                verify=True,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            try:
                d_payload = e.response.json()
            except Exception as exc:
                raise SystemExit(e) from exc
            if "payload" in d_payload and "message" in d_payload["payload"]:
                print("Error: " + d_payload["payload"]["message"])
            raise SystemExit(e) from e
        else:
            public_key = resp.json()["public"]
            if not public_key:
                raise UnableToFetchKeyError(key_type="public")
            private_key = resp.json()["private"]
            if not private_key:
                raise UnableToFetchKeyError(key_type="private")
            return public_key, private_key

    def store_the_keys(self, public_key, private_key):
        """Store the keys in the correct location."""
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            ssh_dir.mkdir()

        # Write private key to file.
        with open(self.private_key_file, "w") as f:
            f.write(private_key)
        os.chmod(self.private_key_file, 0o600)

        # Write public key to file and apply correct permissions.
        with open(self.public_key_file, "w") as f:
            f.write(public_key)
        os.chmod(self.public_key_file, 0o644)

    def _parse_validity_time(self):
        """Parse the validity time from the output."""
        output = subprocess.run(
            ["ssh-keygen", "-L", "-f", self.public_key_file],
            encoding="utf-8",
            capture_output=True,
        ).stdout

        matched_line = (
            re.search(r"^.*{}.*$".format("Valid:"), output, flags=re.MULTILINE)
            .group(0)
            .split()
        )
        start = datetime.fromisoformat(matched_line[2])
        end = datetime.fromisoformat(matched_line[4])
        return start, end

    def key_is_expiring_soon(self):
        """Check if the key is expiring soon."""
        if self.time_left() < timedelta(hours=self.key_warning_threshold):
            return True
        else:
            return False

    def key_is_valid(self):
        """Check if the key is valid."""
        start, end = self._parse_validity_time()
        if start < datetime.now() < end:
            return True
        else:
            return False

    def key_exists(self):
        """Check if the key exists."""
        return self.public_key_file.exists() and self.private_key_file.exists()

    def time_left(self):
        """Check if the key exists."""
        _, end = self._parse_validity_time()
        return end - datetime.now()

    async def _start_periodic_refresh(self, period=2):
        """Start the periodic refresh."""
        while True:
            self.refresh_info()
            await asyncio.sleep(period)

    def refresh_info(self):
        """Refresh the info about the key."""
        if not self.key_exists():
            self.key_validity_info.show(
                "🚫 The SSH key was not found.", danger_level="alert-danger"
            )
            return

        if self.key_is_valid():
            time_left = humanize.naturaldelta(self.time_left())
            if self.key_is_expiring_soon():
                self.key_validity_info.show(
                    f"⚠️ The SSH key is about to expire! Only {time_left} are remaining until it expires.",
                    danger_level="alert-warning",
                )
            else:
                self.key_validity_info.show(
                    f"👍 The SSH key is currently valid and will expire in {time_left}.",
                    danger_level="alert-success",
                )
        else:
            self.key_validity_info.show(
                "🛑 The SSH key is expired.", danger_level="alert-danger"
            )


def get_start_widget(appbase, jupbase, notebase):
    return MfaAuthenicathionWidget()
