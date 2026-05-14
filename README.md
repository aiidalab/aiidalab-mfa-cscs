# MFA for CSCS

AiiDAlab app that obtains a CSCS-signed SSH certificate for connecting to CSCS
supercomputers, without requiring the external `cscs-key` binary.

The app generates an Ed25519 keypair locally (if not present), authenticates
the user against `auth.cscs.ch` via the OAuth2 **device authorization flow**
(or a `CSCS_API_KEY` service token), and posts the public key to the CSCS
SSH-signing service. The resulting certificate is written to
`~/.ssh/cscs-key-cert.pub` and the key is added to `ssh-agent` for 1 day.

## Installation

This Jupyter-based app is intended to be run with [AiiDAlab](https://www.materialscloud.org/aiidalab).

```
aiidalab install aiidalab-mfa-cscs
```

Or directly from the repository:

```
aiidalab install aiidalab-mfa-cscs@git+https://github.com/aiidalab/aiidalab-mfa-cscs
```

## Usage

1. Open the app in AiiDAlab.
2. Choose **Device login** (default) or **API key**.
3. For device login, open the displayed URL in any browser, enter the shown
   code, and authenticate with your CSCS credentials. The widget polls in the
   background and writes the certificate when authorization completes.
4. For API key, paste a token issued from
   [user-account.cscs.ch](https://user-account.cscs.ch).

The widget shows the remaining validity of the current certificate and warns
when it is about to expire.

## License

MIT
