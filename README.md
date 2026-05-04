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
    1. Any additional ports opened at runtime for the TCP/UDP tunnel(s).   
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
The shell script `tunnel.sh` wraps `ssh` and adds automatic reconnection. The server only requires a standard OpenSSH client, which ships with macOS, Linux, and Windows 10 or later. Each example below shows the `tunnel.sh` invocation and the equivalent raw `ssh` command, so you can use the tool without the wrapper script.

First store the domain in a global variable (You can add this to the shell startup)

```
export TUNNEL_DOMAIN=mydomain.io
```

Second, add the client public SSH key as a new entry in the server's authorized keys JSON file (the one passed via `--authorizedKeysFile`).

### Using `ssh` directly (no `tunnel.sh` required)

The raw `ssh` commands below use these conventions so they work the same in **bash**, **zsh**, **PowerShell**, and **cmd.exe**:

* Double quotes around `-R` and the trailing argument. Single quotes are not portable to Windows shells.
* `-o KEY=VALUE` (no spaces) avoids extra quoting.
* `alice` is a placeholder for the `name` field of your entry in [authorized_keys.json](authorized_keys.json). It does NOT need to match your local OS username. Replace `mydomain.io` with your `$TUNNEL_DOMAIN`.
* Add `-i path/to/key` if you need to point at a specific private key.

The trailing quoted string is parsed by the server.

| Field | Purpose |
|---|---|
| `type=` | `http`, `https`, `tcp`, or `udp`.
| `localTarget=` | The local `host:port` your traffic ends up at. Surfaced in server logs for debugging. |
| `tunnelName=` | (*Optional*) Requested subdomain (HTTP/HTTPS only). Server allocates a random one if missing or already taken. |
| `header=` | (*Optional*) Value used to rewrite `Host` and `Origin` on forwarded HTTP requests. |
| `id=` | (*Optional*) Random per-client string used to reclaim the same `tunnelName` after a reconnect. Add one (e.g. a UUID) only if you script reconnect logic yourself. |

### HTTP tunnel via URL path (no subdomain)

If you cannot use subdomains, a single domain can be used for all users using a URL path. For example, to create an HTTP tunnel at local port 3000 (`https://mydomain.io/alice` points to `http://localhost:3000`):

Run the server with
```
./tunnel --domainUrl=https://mydomain.io --domainPath
```
and then create the tunnel on the client:

```
tunnel.sh 3000
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=alice,header=localhost:3000,localTarget=localhost:3000"
```

### HTTP tunnel at a subdomain

Create an HTTP tunnel at local port 3000 (`https://alice.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=alice,header=localhost:3000,localTarget=localhost:3000"
```

Create an HTTP tunnel at local port 3000 at subdomain `abc` (`https://abc.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000 -n abc
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=abc,header=localhost:3000,localTarget=localhost:3000"
```

### HTTP tunnel forwarding to another host

Create an HTTP tunnel for forward host example.com at port 3000 (`https://alice.mydomain.io` points to `http://example.com:3000`):
```
tunnel.sh example.com:3000
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:example.com:3000" alice@mydomain.io "type=http,tunnelName=alice,header=example.com:3000,localTarget=example.com:3000"
```

Create an HTTPS tunnel for forward host example.com at port 443 (`https://alice.mydomain.io` points to `https://example.com`):
```
tunnel.sh example.com:443 --https
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:example.com:443" alice@mydomain.io "type=https,tunnelName=alice,header=example.com:443,localTarget=example.com:443"
```

### TCP tunnel

Create a TCP tunnel at local port 3001 and remote port 5224.
```
tunnel.sh tcp 3001 -p 5224
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:5224:localhost:3001" alice@mydomain.io "type=tcp,localTarget=localhost:3001"
```

### UDP tunnel

Create a UDP tunnel at local port 5353 and remote port 5354.
```
tunnel.sh udp 5353 -p 5354
```

UDP requires the `udp-bridge` helper because SSH only forwards TCP. `tunnel.sh` starts the bridge automatically. If you invoke `ssh` directly, run the bridge yourself in a separate terminal, then forward its TCP listen port:
```
# Terminal 1: start the bridge listening on a fixed TCP port (here 7777)
udp-bridge --bridge=127.0.0.1:7777 --target=localhost:5353

# Terminal 2: forward remote UDP port 5354 to the bridge's TCP port
ssh -p 5223 -R "*:5354:127.0.0.1:7777" alice@mydomain.io "type=udp,localTarget=localhost:5353"
```
On Windows, run `udp-bridge.exe` instead of `udp-bridge`.

### HTTP tunnel with a custom Host header

Some upstream services route on the `Host` header (virtual hosts, multi-tenant gateways). Use `-h` to send a different `Host` than the local target. Forwards traffic to `localhost:3000`, but rewrites the `Host` and `Origin` headers to `api.example.com`:
```
tunnel.sh 3000 -h api.example.com
```
Or with `ssh` directly:
```
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=alice,header=api.example.com,localTarget=localhost:3000"
```

### TCP tunnel with a server-allocated remote port

If you omit `-p` for a TCP tunnel, the server picks a free port and prints it in the connection log. Useful when you do not care which public port is used:
```
tunnel.sh tcp 3001
```
Or with `ssh` directly (port `0` asks the server to choose):
```
ssh -p 5223 -R "*:0:localhost:3001" alice@mydomain.io "type=tcp,localTarget=localhost:3001"
```

### Specifying a private key file

If the matching key is not your default identity, point at it with `-k` (or `-i` for raw `ssh`):
```
tunnel.sh 3000 -k ~/.ssh/id_ed25519_tunnel
```
Or with `ssh` directly:
```
ssh -i ~/.ssh/id_ed25519_tunnel -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=alice,header=localhost:3000,localTarget=localhost:3000"
```
On Windows, use the full path (e.g. `C:\Users\alice\.ssh\id_ed25519_tunnel`).

### Reclaiming the same subdomain after reconnect (raw `ssh`)

`tunnel.sh` automatically generates an `id=` per run so that when the connection drops and the wrapper reconnects, the server recognizes the returning client and hands back the same `tunnelName`. If you script `ssh` yourself, you must supply a stable `id=` value of your own. Pick any long random string and reuse it across reconnects:
```
# bash / zsh
TUNNEL_ID=$(uuidgen)
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=abc,id=$TUNNEL_ID,header=localhost:3000,localTarget=localhost:3000"

# PowerShell
$TUNNEL_ID = [guid]::NewGuid().ToString()
ssh -p 5223 -R "*:80:localhost:3000" alice@mydomain.io "type=http,tunnelName=abc,id=$TUNNEL_ID,header=localhost:3000,localTarget=localhost:3000"
```
Without `id=`, a reconnect after a transient network drop may return a different random subdomain because the server cannot prove the new connection belongs to the previous owner of `abc`.

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

### Raw `ssh` admin commands (no `tunnel.sh`)

Admin requests use a tiny stdin protocol that any OpenSSH client can drive:

* The first line of stdin is the passphrase.
* For `add`, the rest of stdin is the OpenSSH-format public key (one line, same as `~/.ssh/id_ed25519.pub`).
* The remote command is `tunnel-admin <list|add NAME|remove NAME>`.

Read the passphrase into a shell variable. Do NOT type it on the `ssh` command line, because command lines appear in process listings and shell history.
```
# bash / zsh
read -rs -p 'Admin passphrase: ' ADMIN_PASS; echo

# PowerShell (7+)
$ADMIN_PASS = (Read-Host -AsSecureString -Prompt 'Admin passphrase' | ConvertFrom-SecureString -AsPlainText)
```

List authorized keys:
```
# bash / zsh
printf '%s\n' "$ADMIN_PASS" | ssh -p 5223 alice@mydomain.io tunnel-admin list

# PowerShell
$ADMIN_PASS | ssh -p 5223 alice@mydomain.io tunnel-admin list
```

Add a key (`bob` becomes the entry name; `~/keys/bob.pub` is the OpenSSH-format public key):
```
# bash / zsh
printf '%s\n%s' "$ADMIN_PASS" "$(cat ~/keys/bob.pub)" | ssh -p 5223 alice@mydomain.io tunnel-admin add bob

# PowerShell
"$ADMIN_PASS`n$(Get-Content -Raw ~/keys/bob.pub)" | ssh -p 5223 alice@mydomain.io tunnel-admin add bob
```

Remove a key:
```
# bash / zsh
printf '%s\n' "$ADMIN_PASS" | ssh -p 5223 alice@mydomain.io tunnel-admin remove bob

# PowerShell
$ADMIN_PASS | ssh -p 5223 alice@mydomain.io tunnel-admin remove bob
```

Add `-i path/to/key` if the matching identity is not your default key. On Windows `cmd.exe`, multi-line stdin is awkward; use PowerShell or Git Bash for the `add` command.

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
tunnel.sh 3000 -n abc --debug
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
