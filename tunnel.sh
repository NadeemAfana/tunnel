#!/bin/bash
# Creates a TCP or HTTP tunnel between this machine and remote $TUNNEL_DOMAIN.
#
# NOTES:
# The script re-launches ssh when it dies to reconnect automatically.
# It uses an unbuffered pipe to keep the output on screen.
# The SSH server takes the following arguments in the format key=value separated by a comma (eg subdomain=abc,id=19417814394)
# The values are:
#           subdomain:  Optional. The name of the subdomain to use if available. If not specified, the server will use a random name. (HTTP only)
#           header:     Optional. Overrides the HOST header name when executing the HTTP request (HTTP only)
#           id:         Optional. Random string to identify the client session. This is useful for reclaiming the subdomain in case of transient
#                       network errors. Otherwise, when the SSH client reconnects, it will use a different subdomain.

# Adjust the following values to match the server's
sshPort=5223              # server's SSH listening port
serverHttpBindingPort=80  # server's local binding port that listens for incoming HTTP requests
serverTcpBindingPort=0    # server's local binding port that listens for incoming TCP requests. 0 means allocate a random port from the server.


printHelp () {
  printf "Creates a TCP or HTTP tunnel between this machine and remote $TUNNEL_DOMAIN\n"
  printf "Usage:\n"
  printf "  tunnel.sh [http/tcp] [LOCAL_PORT] [-s|--subdomain NAME] [-k, --key FILE]\n"
  printf "            [-p, --remote-port PORT]  [-h|--host HOST] [--debug]\n\n"
  printf "  %-28s Creates an HTTP tunnel at default local port 3000 with\n" "tunnel.sh"
  printf "  %-28s subdomain named after the current user.\n\n"
  printf "  %-28s Creates an HTTP tunnel for forward host example.com at port 3000.\n\n" "tunnel.sh example.com:3000"
  printf "  %-28s Creates an HTTP tunnel at local port 3000 at subdomain 'abc'.\n\n" "tunnel.sh 3000 -s abc"
  printf "  %-28s Creates a TCP tunnel at local port 3001 and remote port 5224.\n\n" "tunnel.sh tcp  3001 -p 5224"
  printf '\nArguments\n'
  printf "  %-25s Uses an HTTP tunnel.\n"  "http, --http"
  printf "  %-25s Uses a TCP tunnel.\n"  "tcp, --tcp"
  
  printf "  %-25s Runs in debug mode where more info is printed on the screen\n"  "--debug"
  printf "  %-25s including parsed command-line args.\n"
  
  printf "  %-25s Selects a file from which the identity (private key) for public key authentication is read.\n"  "-k, --key FILE"
  printf "  %-25s This is passed using -i to SSH.\n"
  
  printf "  %-25s Specifies the name of the HTTP subdomain to take.\n"  "-s, --subdomain SUBDOMAIN"
  printf "  %-25s Use this if you expect to keep the same subdomain after network disconnects.\n"
  printf "  %-25s Overrides the HOST header with the specified value.\n"  "-h, --host HOST"
  printf "  %-25s Uses the specified PORT to listen at on the server side. Defaults to 80 for HTTP.\n"  "-p, --remote-port PORT"

  printf "  %-25s Display this help and exit\n"  "-help, --help"
}

subdomain="$USER"     # default subdomain is the name of the current user
localHostPort="localhost:3000"      # default local  (host) and http/tcp port
remotePort=$serverHttpBindingPort # remote port specified by client
type="http"           # default tunnel type is HTTP
overrideHeaderHost= # override host header with 'localhost:XXX' by default
key=""

# Parse arguments
while [ "$1" != "" ]; do
    case $1 in
        -s | --subdomain)       shift
                                subdomain=$1
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
        tcp | --tcp)            type="tcp"
                                ;;
            --debug)            debug=true
                                ;;                                
        -help | --help )        printHelp
                                exit
                                ;;
        * )                     localHostPort=$1
                                ;;
    esac
    shift
done


if [[ ! $TUNNEL_DOMAIN ]]; then
  echo '$TUNNEL_DOMAIN is required. Try --help for help.'  
  exit 1
fi

if [[ ! $localHostPort ]]; then
  echo 'Local port is required. Try --help for help.'  
  exit 1
fi

if echo "$localHostPort" | grep -qE '^[0-9]+$'; then
  # If port is just a number, prepend 'localhost:'
  localHostPort="localhost:$localHostPort"
fi


if [[ $type = "http" ]]; then  
  httpPort=true
else
  httpPort=false
fi

if [[ -z $overrideHeaderHost && $httpPort ]]; then
    # Set a default host header if not specified
    overrideHeaderHost=$localHostPort
fi

if echo $localHostPort | grep --quiet  -v -xPi '([\.a-z-_]+:?)?\d+$'; then
  echo "Local port $localHostPort is not valid. Try --help for help."
  exit
fi

# Validate the port itself without host
localPort=$(echo $localHostPort | grep -oP '(?<=:)?(\d+)')
if ! [[ -z "${localPort//[0-9]}" &&  $localPort -gt 0 && $localPort -le $((1<<16)) ]]; then
  echo "Local port $localPort is not valid. Try --help for help."
  exit
fi

if ! [[ -z "${remotePort//[0-9]}" &&  $remotePort -ge 0 && $remotePort -le $((1<<16)) ]]; then
  echo "Remote port $remotePort is not a valid port. Try --help for help."
  exit
fi




# Default arguments to pass to SSH server. The default subdomain is the current user name. Override the host header with 'localhost'
sshServerArgs="subdomain=$subdomain,header=$overrideHeaderHost,id=`cat /proc/sys/kernel/random/uuid`"

# Extra args to pass to SSH cli
sshCliArgs=" -o ConnectionAttempts=$((10**4))  -o ServerAliveInterval=20 -o ServerAliveCountMax=2"

if [[ $key  ]]; then
  sshCliArgs="$sshCliArgs -i $key"
fi

if [[ $remotePort == 80 && "$httpPort" = false  ]]; then  
  remotePort=$serverTcpBindingPort
fi

# For debugging
if [[ "$debug" = true ]]; then
  sshCliArgs="$sshCliArgs -v"
  printf "  %-25s $httpPort\n"  "httpPort" 
  printf "  %-25s $type\n"  "type" 
  printf "  %-25s $localHostPort\n"  "localHostPort"
  printf "  %-25s $remotePort\n"  "remotePort"
  printf "  %-25s $TUNNEL_DOMAIN\n"  "domain"
  printf "  %-25s $subdomain\n"  "subdomain"
  printf "  %-25s $sshPort\n"  "sshPort"
  printf "  %-25s $serverHttpBindingPort\n"  "serverHttpBindingPort"
  printf "  %-25s $serverTcpBindingPort\n"  "serverTcpBindingPort"
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
}
trap cleanup EXIT SIGINT


# Use -v for verbose logs and -vv or -vvv for very verbose logs (eg keepalive messages sent from client)
(until ssh  -o 'PubkeyAcceptedKeyTypes +ssh-rsa' -n -p $sshPort $sshCliArgs  -R *:$remotePort:$localHostPort $USER@$TUNNEL_DOMAIN "$sshServerArgs" 2>&1;
do sleep 1
done) > $fifo &
child=$!

# Read output from SSH using th pipe one line at a time and
# print the tunneling http URLs.
stdbuf -oL head $fifo -n $((10**10)) | grep --line-buffered '.*' |
  while IFS= read -r LINE0
  do
    if echo "${LINE0}" | grep -Pq "(http[s]?://.*${TUNNEL_DOMAIN}$|${TUNNEL_DOMAIN}:\d+$)"; then
          s="$localHostPort"
          printf "Tunneling %s -> $s\n" "${LINE0}"
      else
        printf '%s\n' "${LINE0}"
    fi
  done

