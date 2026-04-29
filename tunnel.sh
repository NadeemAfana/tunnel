#!/bin/bash
# Creates a TCP or HTTP tunnel between this machine and remote $TUNNEL_DOMAIN.
#
# NOTES:
# The script re-launches ssh when it dies to reconnect automatically.
# It uses an unbuffered pipe to keep the output on screen.
# The SSH server takes the following arguments in the format key=value separated by a comma (eg tunnelName=abc,id=19417814394)
# The values are:
#           tunnelName: Optional. The tunnel Name (eg subdomain) to use if available. If not specified, the server will use a random name. (HTTP only)
#           header:     Optional. Overrides the HOST header name when executing the HTTP request (HTTP only)
#           id:         Optional. Random string to identify the client session. This is useful for reclaiming the tunnelName in case of transient
#                       network errors. Otherwise, when the SSH client reconnects, it will use a different tunnelName.

# Adjust the following values to match the server's
sshPort=5223              # server's SSH listening port
serverHttpBindingPort=80  # server's local binding port that listens for incoming HTTP requests
serverBindingPort=0       # server's local binding port for TCP/UDP. 0 means allocate a random port from the server.
# Default URL for auto-downloading the udp-bridge helper. Honors a pre-set
# TUNNEL_BRIDGE_URL from the environment so users can pin a specific release
# or point at a different repo without editing this script.
if [[ -z "${TUNNEL_BRIDGE_URL:-}" ]]; then
  TUNNEL_BRIDGE_URL='https://github.com/NadeemAfana/tunnel/releases/latest/download/udp-bridge-{os}-{arch}'
fi

printHelp () {
  printf "Creates a TCP, UDP, or HTTP tunnel between this machine and remote $TUNNEL_DOMAIN\n"
  printf "Usage:\n"
  printf "  tunnel.sh [http/tcp/udp] [LOCAL_PORT] [-n|--tunnelName NAME] [-k, --key FILE]\n"
  printf "            [-p, --remote-port PORT]  [-h|--host HOST] [--debug]\n\n"
  printf "  %-28s Creates an HTTP tunnel at default local port 3000\n" "tunnel.sh"
  printf "  %-28s with tunnelName named after the current user.\n\n"
  printf "  %-28s Creates an HTTP tunnel for forward host\n" "tunnel.sh example.com:3000"
  printf "  %-28s example.com at port 3000.\n\n"
  printf "  %-28s Creates an HTTP tunnel at local port 3000\n" "tunnel.sh 3000 -n abc"
  printf "  %-28s with tunnelName 'abc'.\n\n"
  printf "  %-28s Creates a TCP tunnel at local port 3001\n" "tunnel.sh tcp  3001 -p 5224"
  printf "  %-28s and remote port 5224.\n\n"
  printf "  %-28s Creates a UDP tunnel at local port 5353\n" "tunnel.sh udp  5353 -p 5354"
  printf "  %-28s and remote port 5354.\n\n"
  printf '\nArguments\n'
  printf "  %-25s Uses an HTTP tunnel.\n"  "http, --http"
  printf "  %-25s Uses an HTTPs tunnel.\n"  "https, --https"
  printf "  %-25s Uses a TCP tunnel.\n"  "tcp, --tcp"
  printf "  %-25s Uses a UDP tunnel (requires the udp-bridge helper).\n"  "udp, --udp"

  printf "  %-25s Runs in debug mode where more info is printed\n"  "--debug"
  printf "  %-25s on the screen including parsed command-line args.\n"

  printf "  %-25s Selects a file from which the identity (private\n"  "-k, --key FILE"
  printf "  %-25s key) for public key authentication is read.\n"
  printf "  %-25s This is passed using -i to SSH.\n"

  printf "  %-25s Specifies the name of the HTTP tunnelName to take.\n"  "-n, --tunnelName NAME"
  printf "  %-25s Use this if you expect to keep the same tunnelName\n"
  printf "  %-25s after network disconnects.\n"
  printf "  %-25s Overrides the HOST header with the specified value.\n"  "-h, --host HOST"
  printf "  %-25s Uses the specified PORT to listen at on the server\n"  "-p, --remote-port PORT"
  printf "  %-25s side. Defaults to 80 for HTTP.\n"

  printf "  %-25s Display this help and exit\n"  "-help, --help"
  printf '\nUDP mode\n'
  printf "  UDP tunnels need the udp-bridge helper binary. By default it is cached at\n"
  printf "  \$HOME/.tunnel/udp-bridge. It will be automatically downloaded if not present.\n"
  printf "  Override the binary path via \$UDP_BRIDGE_BIN to use a custom location.\n"
}

tunnelName="$USER"                  # default tunnelName is the name of the current user
localHostPort="localhost:3000"      # default local (host) and http/tcp port
localHostPortSet=false              # tracks whether a positional arg overrode the default
remotePort=""                       # remote port if explicitly given via -p; empty means "use type default"
type="http"                         # default tunnel type is HTTP
overrideHeaderHost=                 # override host header with 'localhost:XXX' by default
key=""

# Parse arguments
while [ "$1" != "" ]; do
    case $1 in
        -n | --tunnelName)      shift
                                tunnelName=$1
                                ;;
        -h | --host)            shift
                                overrideHeaderHost=$1
                                ;;
        -p | --remote-port)     shift
                                remotePort=$1
                                ;;  
        -k | --key)             shift
                                key=$1
                                ;;                                                               
        http | --http)          type="http"
                                ;;
        https | --https)        type="https"
                                ;;
        tcp | --tcp)            type="tcp"
                                ;;
        udp | --udp)            type="udp"
                                ;;
            --debug)            debug=true
                                ;;
        -help | --help )        printHelp
                                exit
                                ;;
        * )                     if [[ "$localHostPortSet" = true ]]; then
                                  echo "tunnel.sh: unexpected extra argument '$1' (already have local target '$localHostPort'). Try --help."
                                  exit 1
                                fi
                                localHostPort=$1
                                localHostPortSet=true
                                ;;
    esac
    shift
done


if [[ ! $TUNNEL_DOMAIN ]]; then
  echo '$TUNNEL_DOMAIN is required. Try --help for help.'  
  exit 1
fi

if echo "$localHostPort" | grep -qE '^[0-9]+$'; then
  # If port is just a number, prepend 'localhost:'
  localHostPort="localhost:$localHostPort"
fi


if [[ $type = "http" || $type = "https" ]]; then  
  httpPort=true
else
  httpPort=false
fi

if [[ -z $overrideHeaderHost && "$httpPort" = true ]]; then
    # Set a default host header if not specified (HTTP/HTTPS only).
    overrideHeaderHost=$localHostPort
fi

# Format check: optional host (letters / digits / dots / dashes / underscores)
# followed by digits. Uses POSIX extended regex so it works with macOS BSD grep
# (no grep -P / PCRE there).
if ! echo "$localHostPort" | grep -qE '^([.a-zA-Z0-9_-]+:?)?[0-9]+$'; then
  echo "Local port $localHostPort is not valid. Try --help for help."
  exit 1
fi

# Extract the port number portion. Bash parameter expansion is portable across
# Linux and macOS (avoids grep -oP / PCRE lookbehind).
localPort="${localHostPort##*:}"
if ! [[ -z "${localPort//[0-9]}" && $localPort -gt 0 && $localPort -lt $((1<<16)) ]]; then
  echo "Local port $localPort is not valid. Try --help for help."
  exit 1
fi

# Empty remotePort means "user did not pass -p; use type default" - defer to
# the type-aware defaulting below. Only validate when explicitly set.
if [[ -n "$remotePort" ]]; then
  if ! [[ -z "${remotePort//[0-9]}" && $remotePort -ge 0 && $remotePort -lt $((1<<16)) ]]; then
    echo "Remote port $remotePort is not a valid port. Try --help for help."
    exit 1
  fi
fi




# UDP mode needs a small helper binary (udp-bridge) on this machine that
# deframes length-prefixed datagrams arriving over the SSH-forwarded TCP
# bridge port and re-emits them as UDP toward the local target. The helper
# is auto-downloaded per OS/arch when missing.
detect_os_arch () {
  local uname_s=$(uname -s)
  local uname_m=$(uname -m)

  case "$uname_s" in
    Linux)                  os="linux" ;;
    Darwin)                 os="darwin" ;;
    MINGW*|MSYS*|CYGWIN*)   os="windows" ;;
    *)
      echo "udp mode: unsupported OS '$uname_s'."
      echo "Set \$UDP_BRIDGE_BIN to a local binary path to bypass auto-download."
      exit 1
      ;;
  esac

  case "$uname_m" in
    x86_64|amd64)           arch="amd64" ;;
    aarch64|arm64)          arch="arm64" ;;
    *)
      echo "udp mode: unsupported architecture '$uname_m'."
      echo "Set \$UDP_BRIDGE_BIN to a local binary path to bypass auto-download."
      exit 1
      ;;
  esac
}

resolve_bridge_binary () {
  # Explicit override wins.
  if [[ -n "${UDP_BRIDGE_BIN:-}" ]]; then
    if [[ ! -x "$UDP_BRIDGE_BIN" ]]; then
      echo "UDP_BRIDGE_BIN=$UDP_BRIDGE_BIN is not an executable file."
      exit 1
    fi
    bridge_bin="$UDP_BRIDGE_BIN"
    return
  fi

  detect_os_arch

  # Default cache location: $HOME/.tunnel/udp-bridge[.exe]
  bridge_bin="$HOME/.tunnel/udp-bridge"
  [[ "$os" == "windows" ]] && bridge_bin="${bridge_bin}.exe"

  if [[ -x "$bridge_bin" ]]; then
    return
  fi

  if [[ -z "${TUNNEL_BRIDGE_URL:-}" ]]; then
    echo "udp mode requires the udp-bridge helper binary at $bridge_bin"
    echo
    echo "Either drop the binary there manually, point \$UDP_BRIDGE_BIN to it,"
    echo "or set \$TUNNEL_BRIDGE_URL to enable auto-download. Example:"
    echo "  export TUNNEL_BRIDGE_URL='https://github.com/NadeemAfana/tunnel/releases/latest/download/udp-bridge-{os}-{arch}'"
    exit 1
  fi

  # Substitute {os} / {arch}; append .exe for Windows assets.
  local url="${TUNNEL_BRIDGE_URL//\{os\}/$os}"
  url="${url//\{arch\}/$arch}"
  [[ "$os" == "windows" ]] && url="${url}.exe"

  echo "udp-bridge not found at $bridge_bin"
  read -p "Download $os/$arch build from $url ? [y/N] " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "Cannot continue without udp-bridge."
    exit 1
  fi

  mkdir -p "$(dirname "$bridge_bin")"
  if ! curl -fSL "$url" -o "$bridge_bin"; then
    echo "Download from $url failed."
    rm -f "$bridge_bin"
    exit 1
  fi
  chmod +x "$bridge_bin"
  echo "Cached udp-bridge at $bridge_bin"
}

start_bridge () {
  # The bridge prints its resolved listen addr on stdout (one line) and
  # everything else on stderr. We capture stdout to a temp file just to
  # learn the addr; stderr inherits this terminal so logs are visible.
  bridgeOut=$(mktemp)
  local extraArgs=""
  [[ "$debug" = true ]] && extraArgs="--debug"
  "$bridge_bin" --bridge=127.0.0.1:0 --target="$localHostPort" $extraArgs >"$bridgeOut" &
  bridgeChild=$!

  local bridgeAddr=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    bridgeAddr=$(head -n1 "$bridgeOut" 2>/dev/null)
    [[ -n "$bridgeAddr" ]] && break
    sleep 0.1
  done
  if [[ -z "$bridgeAddr" ]]; then
    echo "udp-bridge failed to start. Tail of output:"
    cat "$bridgeOut"
    kill $bridgeChild 2>/dev/null
    rm -f "$bridgeOut"
    exit 1
  fi

  echo "udp-bridge listening on $bridgeAddr -> $localHostPort"
  # Re-point ssh -R at the bridge's TCP port, not the UDP service.
  localHostPort="$bridgeAddr"

  # Watcher: if udp-bridge dies, signal the script to exit so the user
  # notices instead of silently losing UDP traffic. ssh would otherwise
  # keep reconnecting and forwarding to a dead local port.
  (
    while kill -0 $bridgeChild 2>/dev/null; do
      sleep 2
    done
    echo "udp-bridge (PID $bridgeChild) died unexpectedly; tunnel.sh exiting." >&2
    kill -TERM $$
  ) &
  bridgeWatcher=$!
}

if [[ "$type" = "udp" ]]; then
  resolve_bridge_binary
  start_bridge
fi

# Default arguments to pass to SSH server. The default tunnelName is the current
# user name. Override the host header with 'localhost'.
# Use uuidgen (works on Linux + macOS) with /proc fallback for stripped-down
# Linux containers that may have neither uuidgen nor util-linux.
sshClientID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null)
sshServerArgs="tunnelName=$tunnelName,type=$type,header=$overrideHeaderHost,id=$sshClientID"

# Extra args to pass to SSH cli
sshCliArgs=" -o ConnectionAttempts=$((10**4))  -o ServerAliveInterval=20 -o ServerAliveCountMax=2"

if [[ $key  ]]; then
  sshCliArgs="$sshCliArgs -i $key"
fi

# Type-aware default for remotePort if -p wasn't given.
if [[ -z "$remotePort" ]]; then
  if [[ "$httpPort" = true ]]; then
    remotePort=$serverHttpBindingPort
  else
    remotePort=$serverBindingPort
  fi
fi

# For debugging
if [[ "$debug" = true ]]; then
  sshCliArgs="$sshCliArgs -v"
  printf "  %-25s $httpPort\n"  "httpPort" 
  printf "  %-25s $type\n"  "type" 
  printf "  %-25s $localHostPort\n"  "localHostPort"
  printf "  %-25s $remotePort\n"  "remotePort"
  printf "  %-25s $TUNNEL_DOMAIN\n"  "domain"
  printf "  %-25s $tunnelName\n"  "tunnelName"
  printf "  %-25s $sshPort\n"  "sshPort"
  printf "  %-25s $serverHttpBindingPort\n"  "serverHttpBindingPort"
  printf "  %-25s $serverBindingPort\n"  "serverBindingPort"
  printf "  %-25s $overrideHeaderHost\n"  "overrideHeaderHost"
  printf "  %-25s $sshCliArgs\n"  "sshCliArgs"
  printf "\n"
fi


# Create a pipe for capturing output from SSH
fifo="$(mktemp)"
if [ $? -ne 0 ]; then
    echo "$0: Could not create temp file for pipe."
    exit 1
fi
rm $fifo
mkfifo $fifo

# Clean up on script exit
function cleanup {
  rm -f $fifo
  kill $child > /dev/null 2>&1
  if [[ -n "${bridgeWatcher:-}" ]]; then
    kill $bridgeWatcher > /dev/null 2>&1
  fi
  if [[ -n "${bridgeChild:-}" ]]; then
    kill $bridgeChild > /dev/null 2>&1
  fi
  if [[ -n "${bridgeOut:-}" ]]; then
    rm -f "$bridgeOut"
  fi
}
trap cleanup EXIT SIGINT SIGTERM


# Use -v for verbose logs and -vv or -vvv for very verbose logs (eg keepalive messages sent from client)
(until ssh  -o 'PubkeyAcceptedKeyTypes +ssh-rsa' -n -p $sshPort $sshCliArgs  -R "*:$remotePort:$localHostPort" $USER@$TUNNEL_DOMAIN "$sshServerArgs" 2>&1;
do sleep 1
done) > $fifo &
child=$!

# Read output from SSH using th pipe one line at a time and
# print the tunneling http URLs.
stdbuf -oL head $fifo -n $((10**10)) | grep --line-buffered '.*' |
  while IFS= read -r LINE0
  do    
    if echo "${LINE0}" | grep -Pq "^(http[s]?://.*${TUNNEL_DOMAIN}|${TUNNEL_DOMAIN}:\d+)"; then
          # The first line is always the full tunnel http URL
          s="$localHostPort"
          printf "Tunneling %s -> $s\n" "${LINE0}"
      else
        printf '%s\n' "${LINE0}"
    fi
  done