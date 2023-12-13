# HTTP and TCP Tunnel
Built using plain Go framework and has no external dependencies for the tunnel implementation. 
It works by using SSH por forwarding for the tunnels.
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
1. Create an `authorized_keys_enc` env variable which is the base64 value of the list of all client public SSH keys (each key separated by line feed. The key format is SHA256. See https://tools.ietf.org/html/rfc4648#section-3.2).  Each client that wants to connect must have their public key added to a whitelist list. 
1. The tunnel requires a **DNS domain** to work. The domain and all subdomains must point to the server for the http tunnel to work. 
The app will assign a unique subdomain for each HTTP client. For example, if your DNS domain is  `abc.io`, then `x.abc.io` and all subdomains (ie `*.abc.io`) must point to the server.
1. The following TCP ports must be open on the server
    1. **80** for incoming http traffic.
    1. **5223** for SSH.
    1. Any additional ports opened at runtime for the TCP tunnel(s).   
2. Run the server 
    ```
    CGO_ENABLED=0 go build
    ./tunnel --domain=mydomain.io
    ```

    For Docker
    ```
     docker build . -t=tunnel
     docker run -p 80:80 -p 5223:5223 -e authorized_keys_enc='cfhJklQ=' -e ssh_host_key_enc='LS0tCg==' tunnel

    ```

## Client Setup
The shell script `tunnel.sh` wraps `ssh` and allows the client to connect to the server in the following way.

First store the DNS in a global variable (You can add this to the shell startup)

```
export TUNNEL_DOMAIN=mydomain.io
```

Second, add the client public SSH key to the server `authorized_keys_enc` env variable.

Creates an HTTP tunnel at local port 3000 (`https://username.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000 
```

Creates an HTTP tunnel at local port 3000 at subdomain 'abc' (`https://abc.mydomain.io` points to `http://localhost:3000`):
```
tunnel.sh 3000 -s abc
```

 Creates an HTTP tunnel for forward host example.com at port 3000 (`https://username.mydomain.io` points to `http://example.com:3000`):
```
tunnel.sh example.com:3000
```


Creates a TCP tunnel at local port 3001 and remote port 5224.
```
tunnel.sh tcp  3001 -p 5224
```

For debugging and troubleshooting, append `--debug`
```
tunnel.sh 3000 -s abc --debug
```


For more info
```
tunnel.sh --help
```

# Unit Tests
To run the unit tests
```
go test
```
