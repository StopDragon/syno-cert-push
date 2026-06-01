# syno-cert-push

Push the TLS certificate that **Nginx Proxy Manager (NPM)** already issues and
renews into **Synology DSM** automatically -- so services that bypass the reverse
proxy (e.g. **Synology Drive on port 6690**) always serve a fresh certificate
without the quarterly manual export/import dance.

## Why

NPM renews its own certificate, but it can only serve ports it proxies. The
Synology Drive desktop client connects on TCP **6690**, which is not an HTTP
service and is typically port-forwarded straight to the NAS -- so the NAS itself
must hold the certificate. This script closes that gap: it watches NPM's
certificate and pushes any change into DSM via the official WebAPI.

## How it works

1. **Locates the cert by domain (SAN)** under NPM's `letsencrypt/live/npm-*`, so
   it keeps working even when NPM's `npm-N` index changes after a re-issue.
2. **Detects renewal** by comparing the `fullchain.pem` hash; it only pushes when
   the certificate actually changed.
3. **Pushes via DSM WebAPI** (`SYNO.Core.Certificate` import), replacing the
   existing certificate in place so the service mapping (incl. 6690) is kept.
4. **2FA via device_id** -- register once with `--init` (enter an OTP), then it
   logs in without OTP. No TOTP secret stored on disk.

## Requirements

- A host that can reach DSM's admin port (the NPM server is ideal)
- `bash`, `curl`, `openssl`, `jq`
- A Synology account in the **administrators** group (a dedicated `acme` user is recommended)

## Install

```bash
git clone https://github.com/StopDragon/syno-cert-push.git
cd syno-cert-push
sudo ./install.sh
```

The installer probes for the NPM cert path, writes `/etc/syno-cert-push.conf`
(chmod 600), registers the 2FA device, and offers to add a daily cron job.

## Manual setup

```bash
cp syno-cert-push.conf.example /etc/syno-cert-push.conf   # edit, then chmod 600
sudo install -m 0755 syno-cert-push.sh /usr/local/bin/syno-cert-push
sudo SYNO_CERT_CONF=/etc/syno-cert-push.conf syno-cert-push --init   # OTP once
```

Cron (daily; actual push happens only when NPM renews):

```cron
0 4 * * * SYNO_CERT_CONF=/etc/syno-cert-push.conf /usr/local/bin/syno-cert-push >> /var/log/syno-cert-push.log 2>&1
```

Finally, in DSM **Control Panel > Security > Certificate > Settings**, map
Synology Drive (6690) to the certificate once. Done.

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| Login error **403** in auto mode | `device_id` expired -> run `--init` again |
| **404** at login | Wrong OTP code |
| **105** on import | Account is not in the *administrators* group |
| "cert not found" | `DRIVE_DOMAIN` / `NPM_LIVE_DIR` mismatch; check the SAN of the live cert |

## Security notes

- The config holds the DSM password; it is written `0600`. Use a dedicated
  least-privilege admin account.
- `device_id` (not a TOTP secret) is stored under `STATE_DIR` (`0700`).

## License

MIT -- see [LICENSE](LICENSE).
