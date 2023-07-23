# HTTP and TCP Tunnel
Built using plain Go framework and has no external dependencies for the tunnel implementation. It works by using SSH for the tunnels.
The tool supports the following features:

1. The client side can use the `ssh` command-line tool and thus requires no additional installations.
1. Reconnects automatically on the client side when connection dies and is able to re-use the same subdomain to avoid disruption. 
1. Rewrites the `Origin` and `Host` headers for HTTP tunnels.
1. The HTTP tunnel requires a DNS domain to work. The domain and all subdomains must point to the server. 
The app will assign a unique subdomain for each HTTP client. For example, if your DNS domain is  `abc.io`, then `x.abc.io` and all subdomains (ie `*.abc.io`) must point to the server.
1. Can be hosted behind reverse-proxy and anywhere in the cloud, k8s, etc.


# Server Setup
1. Create a `secrets.env` file that contains 2 entries: `authorized_keys.enc` and `ssh_host_key.enc`.
    1. The `ssh_host_key.enc` entry contains the base64 value of the SSH host-specific private key, which is used to identify the host. You can generate a new key using the command `ssh-keygen -t ecdsa -f /tmp/ssh` to generate the file and then base64 encode it `cat /tmp/ssh | base64 -w 0`.
    Each client that want to connect must have their public key added to the list. The list of all keys is base64 encoded.
    1. The `authorized_keys.enc` entry contains a list of all the client public SSH keys separated by a new line.
    1. A sample `secrets.env` would look like the following
        ```
        authorized_keys.enc=c3NoLXJzYSBBQUFBQjNOemFDMXljMkVB=
        ssh_host_key.enc=LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEU==
        ```
2. Run the server 
    ```
    go build
    ./tunnel --domain mydomain.io
    ```

## Client Setup
The shell script `tunnel.sh` wraps `ssh` and allows the client to connect to the server in the following way.

First store the DNS in a global variable (You can add this to the shell startup)

```
export TUNNEL_DOMAIN=mydomain.io
```

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

