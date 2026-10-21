# Security and TLS

Drivers give the daemon access to real devices, so anyone who can connect to the daemon may be able to read sensor data or control equipment. Protect each layer:

- **Network access:** listen only on the interfaces you need, and use TLS whenever traffic leaves the local machine.
- **User accounts:** give every client and remote link its own account with only the rights it needs.
- **Files:** restrict configuration files, password hashes, and private keys to the daemon account and administrators.

## Limit where the daemon listens

The TCP/IP server listens on the address set by `tcpip.interface-address`. If the setting is missing, the daemon listens on `tcp://localhost:9598`, which accepts connections only from the same machine. This is the safest starting point.

To accept connections from other machines, set an explicit address. The URL scheme selects plain TCP or TLS:

| Address | Meaning |
| :------ | :------ |
| `tcp://localhost:9598` | Plain TCP, local connections only (default). |
| `tcp://192.0.2.20:9598` | Plain TCP on one network interface. Use only on a trusted network. |
| `tls://0.0.0.0:9598` | TLS on all IPv4 interfaces. |
| `tls://192.0.2.20:9598` | TLS on one network interface. |

The daemon has a single TCP/IP listener, so it accepts either plain TCP or TLS connections, not both. When you switch to TLS, update every client and every TCP/IP Link driver that connects to the daemon.

## Set up TLS

TLS encrypts the connection and lets clients verify that they are talking to the right server. The daemon uses OpenSSL and accepts TLS 1.2 or later.

### 1. Create a certificate and private key

For production, use a certificate issued by your organisation's certificate authority (CA) or by a public CA. The certificate must name the host or IP address that clients use to connect.

For testing, you can create a self-signed certificate. Replace the host name and IP address with your own:

```bash
sudo install -d -o root -g vscp -m 0750 /etc/vscp/certs
sudo openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -keyout /etc/vscp/certs/tcpip_server.key \
  -out /etc/vscp/certs/tcpip_server.crt \
  -subj "/CN=vscp.example.com" \
  -addext "subjectAltName=DNS:vscp.example.com,IP:192.0.2.20"
sudo chown root:vscp /etc/vscp/certs/tcpip_server.key /etc/vscp/certs/tcpip_server.crt
sudo chmod 0640 /etc/vscp/certs/tcpip_server.key
sudo chmod 0644 /etc/vscp/certs/tcpip_server.crt
```

Both files must be in PEM format. The private key must not be protected by a passphrase, because the daemon cannot prompt for one at startup; protect it with file permissions instead. If your service runs as a different account, replace the `vscp` group accordingly.

The certificates in the repository's `install/certs` folder are examples only. Never use them in production, because their private keys are public.

### 2. Enable TLS in `vscpd.json`

Set a `tls://` address and point `ssl-options` at the certificate and key:

```json
{
  "tcpip": {
    "interface-address": "tls://0.0.0.0:9598",
    "ssl-options": {
      "certfile": "/etc/vscp/certs/tcpip_server.crt",
      "keyfile": "/etc/vscp/certs/tcpip_server.key",
      "cafile": ""
    }
  }
}
```

| Setting | Description |
| :------ | :---------- |
| `certfile` | Server certificate in PEM format. Include any intermediate CA certificates after the server certificate. |
| `keyfile` | Unencrypted private key for the server certificate, in PEM format. |
| `cafile` | Leave empty for normal server-only TLS. If set, clients **must** present a certificate signed by one of these CAs (see below). |

The daemon reads these files at startup. Restart the daemon after you change or renew a certificate.

### 3. Test the connection

Use `openssl s_client` to check that the server presents the expected certificate and accepts a login. For a self-signed certificate, pass the certificate as the trusted CA:

```bash
openssl s_client -connect vscp.example.com:9598 \
  -CAfile /etc/vscp/certs/tcpip_server.crt \
  -servername vscp.example.com -verify_hostname vscp.example.com \
  -verify_return_error -quiet -crlf
```

When the connection succeeds, the daemon sends its `+OK` greeting. You can then type VSCP Link Protocol commands such as `user`, `pass`, and `vers`. A verification error usually means the host name does not match the certificate or the client does not trust the CA.

### Optional: require client certificates

For mutual TLS, set `cafile` to the PEM file containing the CA certificates that are allowed to issue client certificates:

```json
"ssl-options": {
  "certfile": "/etc/vscp/certs/tcpip_server.crt",
  "keyfile": "/etc/vscp/certs/tcpip_server.key",
  "cafile": "/etc/vscp/certs/client_ca.crt"
}
```

The daemon then rejects any TLS client that does not present a valid certificate from one of these CAs. Clients must still log in with a username and password, so client certificates add a second layer of protection rather than replacing accounts.

To test mutual TLS, add the client's certificate and key to the `openssl s_client` command:

```bash
openssl s_client -connect vscp.example.com:9598 \
  -CAfile /etc/vscp/certs/tcpip_server.crt \
  -servername vscp.example.com -verify_hostname vscp.example.com \
  -verify_return_error -cert client.crt -key client.key -quiet -crlf
```

## Use a free certificate from Let's Encrypt

[Let's Encrypt](https://letsencrypt.org/) issues free, publicly trusted TLS certificates. Unlike the self-signed test certificate above, a Let's Encrypt server certificate is normally trusted by clients using an up-to-date system CA store. You still need to control the domain name, protect the private key, and renew the certificate automatically.

The following Debian/Ubuntu example uses [Certbot](https://certbot.eff.org/), the host name `vscp.example.com`, and a daemon running with group `vscp`. Replace the host name, email address, and group with your own values. These are instructions to run on your server, not certificates bundled with VSCP.

### 1. Choose how to prove control of the domain

- **HTTP-01:** the domain's public DNS `A` and, if present, `AAAA` records must lead to a server that can answer the challenge on TCP port **80**. Forward this port through NAT if necessary. Port 9598 is not used for validation.
- **DNS-01:** use a DNS-provider plugin to create a temporary TXT record. This works even if the daemon is on a private network and cannot expose port 80. Prefer a plugin with an API so renewal can be automated.

HTTP-01 does not require the daemon's VSCP port to be publicly accessible. Conversely, opening port 9598 does not make an HTTP-01 challenge work.

### 2. Obtain the certificate with Certbot

Install Certbot using the [instructions for your operating system](https://certbot.eff.org/instructions). For Debian/Ubuntu distribution packages:

```bash
sudo apt update
sudo apt install certbot
sudo certbot certonly --standalone \
  --cert-name vscp.example.com \
  --domain vscp.example.com \
  --email administrator@example.com --agree-tos
```

The standalone authenticator temporarily listens on port 80. If another web server already uses that port, use its existing web root instead of stopping it without a plan:

```bash
sudo certbot certonly --webroot --webroot-path /var/www/html \
  --cert-name vscp.example.com \
  --domain vscp.example.com \
  --email administrator@example.com --agree-tos
```

For the web-root alternative, the existing HTTP server must serve `http://vscp.example.com/.well-known/acme-challenge/` from that directory. Choose **one** authenticator; do not run both commands for the same setup.

Certbot creates a certificate lineage under `/etc/letsencrypt/live/vscp.example.com/`:

| File | Purpose |
| :--- | :------ |
| `fullchain.pem` | Server certificate followed by intermediate CA certificates. Use this for the daemon's `certfile`. |
| `privkey.pem` | Server private key. Use this for `keyfile`, but keep it private. |

Use `sudo certbot certificates` to check the actual lineage path and expiry date. The explicit `--cert-name` above makes the deployment hook below predictable.

### Alternative: use DNS validation for a private server

For example, if your DNS zone is managed by Cloudflare, install its Certbot plugin:

```bash
sudo apt install python3-certbot-dns-cloudflare
sudo install -d -m 0700 /root/.secrets/certbot
sudoedit /root/.secrets/certbot/cloudflare.ini
```

Put a restricted API token in that file:

```ini
dns_cloudflare_api_token = REPLACE_WITH_YOUR_RESTRICTED_API_TOKEN
```

Grant only the DNS-edit permissions needed for your zone, not access to your entire account. Then protect the file and request the certificate:

```bash
sudo chmod 0600 /root/.secrets/certbot/cloudflare.ini
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/certbot/cloudflare.ini \
  --cert-name vscp.example.com \
  --domain vscp.example.com \
  --email administrator@example.com --agree-tos
```

Use your provider's plugin and credential format if you do not use Cloudflare. See the [Cloudflare plugin documentation](https://certbot-dns-cloudflare.readthedocs.io/en/stable/) and [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/) for details. Manual DNS challenges require manual updates on renewal unless you supply automation hooks; they are not a substitute for unattended renewal.

### 3. Configure the daemon and deploy readable copies

Certbot's private key and archive directories are normally restricted to root. Do not make `/etc/letsencrypt` world-readable or run the daemon as root just to read them. Instead, deploy the two files to the protected directory used in the TLS example:

```json
{
  "tcpip": {
    "interface-address": "tls://0.0.0.0:9598",
    "ssl-options": {
      "certfile": "/etc/vscp/certs/tcpip_server.crt",
      "keyfile": "/etc/vscp/certs/tcpip_server.key",
      "cafile": ""
    }
  }
}
```

Merge this into `vscpd.json`, preserving your other settings. Leave `cafile` empty for server-only TLS: it is **not** where you put the Let's Encrypt chain. Setting it enables client-certificate requirements.

Create a root-owned deploy hook:

```bash
sudo install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
sudoedit /etc/letsencrypt/renewal-hooks/deploy/vscpd
```

Save the following script in that file. Adjust the lineage, service name, and daemon group if yours differ:

```sh
#!/bin/sh
set -eu

if [ "${RENEWED_LINEAGE:-}" != "/etc/letsencrypt/live/vscp.example.com" ]; then
  exit 0
fi

install -d -o root -g vscp -m 0750 /etc/vscp/certs
install -o root -g vscp -m 0644 \
  "$RENEWED_LINEAGE/fullchain.pem" /etc/vscp/certs/tcpip_server.crt
install -o root -g vscp -m 0640 \
  "$RENEWED_LINEAGE/privkey.pem" /etc/vscp/certs/tcpip_server.key
systemctl restart vscpd
```

The lineage check prevents a renewal for some other service from replacing the daemon's certificate. Certbot runs the hook as root after a successful renewal. File-copy failures stop the script before the restart.

Make the hook executable, then run it once to deploy the initial certificate and restart the daemon:

```bash
sudo chown root:root /etc/letsencrypt/renewal-hooks/deploy/vscpd
sudo chmod 0750 /etc/letsencrypt/renewal-hooks/deploy/vscpd
sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/vscp.example.com \
  /etc/letsencrypt/renewal-hooks/deploy/vscpd
```

Check the daemon log immediately. A restart disconnects existing clients, so arrange for them to reconnect.

### 4. Enable and test automatic renewal

For the Debian/Ubuntu packages above, enable the scheduled renewal service and perform a staging renewal test:

```bash
sudo systemctl enable --now certbot.timer
sudo systemctl list-timers --all certbot.timer
sudo certbot renew --cert-name vscp.example.com --dry-run
```

Other Certbot installation methods may install a differently named timer or a cron job. Verify that **one** renewal scheduler is active. Keep the selected challenge working: standalone HTTP validation still needs port 80 to be available on future renewals, while DNS validation still needs valid API credentials.

The daemon keeps the certificate in memory, so renewal alone is not enough: the deploy hook must copy the renewed files and restart the service. A plain `--dry-run` tests validation but does not normally run deploy hooks. On Certbot versions supporting it, `--dry-run --run-deploy-hooks` also tests deployment using the current live certificate; it restarts the daemon, so run it during a suitable maintenance window.

Monitor renewal failures and expiry rather than relying on a fixed certificate lifetime. See [Certbot's renewal documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

### 5. Verify public trust and the host name

From a Debian/Ubuntu client with an up-to-date CA bundle:

```bash
openssl s_client -connect vscp.example.com:9598 \
  -servername vscp.example.com -verify_hostname vscp.example.com \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -verify_return_error -quiet -crlf
```

Use your client's system CA bundle path on other platforms. Do not disable verification to hide a failure. Connect using the certificate's DNS name, even for a private server; a certificate for `vscp.example.com` does not automatically validate a connection made using an IP address.

After the TLS handshake, the daemon sends its greeting and still requires a VSCP account login. See the [Link command reference](./tcpip_link_commands.md) for an example session.

## Create user accounts

Clients log in with an account from the `remoteuser` array. Passwords are stored as Argon2id hashes, never as plain text. Generate a hash with the `mk_password_hash` tool, which is built with the daemon:

```bash
mk_password_hash 'a-long-unique-password'
```

Copy the complete output, starting with `$argon2id$`, into the `password` field:

```json
{
  "remoteuser": [
    {
      "username": "dashboard",
      "password": "$argon2id$v=19$m=262144,t=3,p=1$REPLACE_WITH_GENERATED_HASH",
      "fullname": "Dashboard client",
      "privilege": "user",
      "allowed_remotes": "-0.0.0.0/0,+192.0.2.0/24,+127.0.0.1",
      "allowed_events": "000A:*,0014:*",
      "filter": "",
      "mask": ""
    }
  ]
}
```

| Setting | Description |
| :------ | :---------- |
| `username` | The name used with the `USER` command. Each name must be unique. |
| `password` | The Argon2id hash produced by `mk_password_hash`. Accounts with an empty password are ignored. |
| `privilege` | Rights for the account. Use `admin`, `user`, or `driver`, or combine individual rights with `/`, for example `receive-events/send-events`. Avoid `admin` except for administrators. |
| `allowed_remotes` | Comma-separated IPv4 rules. Each rule starts with `+` (allow) or `-` (deny) followed by an address or network in CIDR form. Rules are checked in order and the last matching rule wins. If no rule matches, or the list is empty, the connection is **allowed**. |
| `allowed_events` | Comma-separated `class:type` pairs, in four-digit hexadecimal, that the user may send. Use `*` as a type wildcard (`000A:*`) or `*:*` for all events. An empty value allows all events. |
| `filter`, `mask` | Optional receive filter and mask that limit which events are delivered to the client. Both must be set for the filter to apply. |

To restrict an account, start `allowed_remotes` with `-0.0.0.0/0` to deny everything, then add `+` rules for the hosts or networks that may connect, as in the example above.

## Secure driver connections

- **Driver configuration files:** store files that contain passwords or keys, such as `tcpiplink.json`, in `/etc/vscp`. Make them readable only by the daemon account (for example, owner `root`, group `vscp`, mode `0640`).
- **TCP/IP Link driver:** create a dedicated account on the remote system with only the rights the link needs. If the remote system uses TLS, configure the driver's `tls` section to verify the remote certificate; see the [driver documentation](https://github.com/grodansparadis/vscpl2drv-tcpiplink).
- **Linking two daemons:** when one daemon connects to another over TLS, the connecting driver acts as a TLS client. Give it the CA certificate that signed the remote daemon's certificate.
- **Logger output:** event logs can reveal device activity. Restrict access to the log directory in the same way as configuration files.

## Security checklist

- Keep the default `localhost` listener unless remote clients need access.
- Use `tls://` for any listener reachable from another machine.
- Use a certificate whose name matches the address clients use, and protect its private key.
- Give each client its own account, with a strong password stored as an Argon2id hash.
- Limit each account with `privilege`, `allowed_remotes`, and `allowed_events`.
- Restrict access to `vscpd.json`, driver configuration files, keys, and logs.
- Restart the daemon after changing certificates, users, or drivers, then check the log for errors.

See [Security](./security_general.md) for background on VSCP encryption and password handling.

[filename](./bottom_copyright.md ':include')
