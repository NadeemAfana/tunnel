# HTTP, TCP, and UDP Tunnel
Built using plain Go framework and has no external dependencies for the tunnel implementation.
It works by using SSH port forwarding for the tunnels.
The tool supports the following features:

1. The client side can use the `ssh` command-line tool and thus requires no additional installations.
1. Reconnects automatically on the client side when connection dies and is able to re-use the same subdomain to avoid disruption. 
1. Rewrites the `Origin` and `Host` headers for HTTP tunnels.
1. Can be hosted behind reverse-proxy and anywhere in the cloud, k8s, etc.

# Why Use This If There Are Alternatives
1. Security and transparency if you want 100% control over the full traffic. That's why I mainly built this.
1. It's FREE and has no limitation on its usage.

# Server Setup
1. Create an `ssh_host_key_enc` env variable that contains the base64 value of the SSH host-specific private key which is used to identify the host. You can generate a new key using the command `ssh-keygen -t ecdsa -f /tmp/ssh` to generate the file and then base64 encode it `cat /tmp/ssh | base64 -w 0`.
1. Create an authorized keys JSON file and pass its path to the server with `--authorizedKeysFile=/etc/tunnel/authorized_keys.json`. Each client that wants to connect must have their public key added to this file. The format is:

    ```json
    {
      "keys": [
        { "name": "alice", "publicKey": "ssh-ed25519 AAAA... alice@example.com" },
        { "name": "bob",   "publicKey": "ssh-rsa AAAA... bob" }
      ]
    }
    ```

    The `name` is used in server logs to identify which client connected. The `publicKey` is the same single-line format you would put in an OpenSSH `authorized_keys` file.
1. (Optional) Enable runtime admin commands so authorized keys can be added or removed without restarting the server. Generate a bcrypt hash of an admin passphrase using the tunnel binary itself (no external tools required) and set it as `admin_passphrase_bcrypt`:

    ```
    read -rs -p 'Admin passphrase: ' p; echo
    echo -n "$p" | ./tunnel --genAdminHash
    # copy the printed $2a$12$... hash into the env var
    export admin_passphrase_bcrypt='$2a$12$...'
    ```

    If `admin_passphrase_bcrypt` is unset, the server logs `Admin commands disabled` on startup and rejects any admin request. See [Managing Authorized Keys at Runtime](#managing-authorized-keys-at-runtime) below for the client commands.
1. The tunnel requires a **DNS domain** to work. The domain and all subdomains must point to the server for the http tunnel to work unless the option `--domainPath` is used. 
The app will assign a unique subdomain for each HTTP client. For example, if your DNS domain is  `abc.io`, then `x.abc.io` and all subdomains (ie `*.abc.io`) must point to the server.
1. The following TCP ports must be open on the server
    1. **80** for incoming http traffic.
    1. **5223** for SSH.
    1. Any additional ports opened at runtime for the TCP tunnel(s).   
2. Run the server 
    ```
    CGO_ENABLED=0 go build
    ./tunnel --domainUrl=https://mydomain.io --authorizedKeysFile=/etc/tunnel/authorized_keys.json
    ```

    For Docker (multi-stage build - no host Go toolchain required; mount the keys file into the container)
    ```
     docker build . -t=tunnel
     docker run -p 80:80 -p 5223:5223 \
       -e ssh_host_key_enc='LS0tCg==' \
       -v /etc/tunnel/authorized_keys.json:/etc/tunnel/authorized_keys.json:ro \
       tunnel \
         --domainUrl=https://mydomain.io \
         --authorizedKeysFile=/etc/tunnel/authorized_keys.json

    ```

## Client Setup
The shell script `tunnel.sh` wraps `ssh` and allows the client to connect to the server in the following way.

First store the domain in a global variable (You can add this to the shell startup)

```
export TUNNEL_DOMAIN=mydomain.io
```

Second, add the client public SSH key as a new entry in the server's authorized keys JSON file (the one passed via `--authorizedKeysFile`).

If you cannot use subdomains, a single domain can be used for all users using a URL path. For example, to create an HTTP tunnel at local port 3000 (`https://mydomain.io/username` points to `http://localhost:3000`):

Run the server with 
```
./tunnel --domainUrl=https://mydomain.io --domainPath
```
and then create the tunnel on the client:

```
tunnel.sh 3000
```

Create an HTTP tunnel at local port 3000 (`https://username.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000 
```

Create an HTTP tunnel at local port 3000 at subdomain 'abc' (`https://abc.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000 -s abc
```

Create an HTTP tunnel for forward host example.com at port 3000 (`https://username.mydomain.io` points to `http://example.com:3000`):
```
tunnel.sh example.com:3000
```

Create an HTTPS tunnel for forward host example.com at port 3000 (`https://username.mydomain.io` points to `https://example.com`):
```
tunnel.sh example.com:443 --https
```

Create a TCP tunnel at local port 3001 and remote port 5224.
```
tunnel.sh tcp  3001 -p 5224
```

Create a UDP tunnel at local port 5353 and remote port 5354.
```
tunnel.sh udp  5353 -p 5354
```

## Managing Authorized Keys at Runtime

Once the server is running with `admin_passphrase_bcrypt` set, any client whose key is currently authorized can add or remove keys without a server restart. Changes are applied to the in-memory list immediately and survive only until the next restart - to make them permanent, copy the JSON snippet emitted in the server log into [authorized_keys.json](authorized_keys.json).

The admin passphrase is read silently from the controlling terminal, or from the `TUNNEL_ADMIN_PASSPHRASE` env var if set. It is sent on the first stdin line of the SSH exec - never on the command line, so it does not appear in process listings or shell history.

List all currently authorized keys:
```
tunnel.sh admin list
```

Add a new key (the public-key file is the same single-line OpenSSH format as `~/.ssh/id_ed25519.pub`):
```
tunnel.sh admin add bob --pubkey ~/keys/bob.pub
```

Remove a key by name:
```
tunnel.sh admin remove bob
```

Specify a non-default identity file with `-k`:
```
tunnel.sh admin list -k ~/.ssh/admin_id_ed25519
```

Each successful mutation produces a `WARNING`-level log line on the server containing the calling key's name, the affected key's name, the SHA256 fingerprint, and the exact JSON entry to add to (or remove from) `authorized_keys.json`. Failed attempts (wrong passphrase) are also logged so the operator can spot brute-force attempts.

Two safety rails are enforced:
- A key cannot remove itself (would lock the caller out).
- Names and public keys must be unique - adding a duplicate is rejected.

UDP mode requires a small helper binary (`udp-bridge`) on the client. By default `tunnel.sh` looks for it at `$HOME/.tunnel/udp-bridge` (`.exe` on Windows). To enable auto-download, set `TUNNEL_BRIDGE_URL` with `{os}` / `{arch}` placeholders pointing at your release assets:

```
export TUNNEL_BRIDGE_URL='https://github.com/owner/repo/releases/latest/download/udp-bridge-{os}-{arch}'
```

Supported `{os}-{arch}` combinations: `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`. Build them all with:

```
./build-bridge.sh
```

To use a custom binary location instead, set `UDP_BRIDGE_BIN` to the absolute path of the executable.

For debugging and troubleshooting, append `--debug`
```
tunnel.sh 3000 -s abc --debug
```


For more info
```
tunnel.sh --help
```

# Tests
To run the tests
```
go test
```
