#!/bin/bash
#
# This script will scan AWS instances for occurrences of IOC hashes listed in
# the blob at src/ioc_scan/ioc_scanner.py
#
# The filename specified in the first argument
# (instance-list-file) should contain a list of instance id strings, one per line.
#
# The following environment variables must be set:
# AWS_SHARED_CREDENTIALS_FILE
# AWS_REGION
# AWS_PROFILE
#
# Usage: ./ioc_hash_scan.sh instance-list-file
#
# This script assumes that it exists in the ioc-scanner/extras/ directory.
# If it does not, please edit the variable $pydir to point to
# the directory containing ioc_scanner.py

set -o nounset
set -o errexit
set -o pipefail

# Directory path of the ioc_scanner.py file
pydir="../src/ioc_scan/"

if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -gt 1 ]; then
  echo Usage: "$0" instance-list-file
  exit 1
fi

# Check if instance list file exists.
if [ ! -f "$1" ]; then
  echo Instance List file "$1" does not exist - exiting.
  exit 1
fi

# Check if environment variables are set
CRED=$(env | grep AWS_SHARED_CREDENTIALS_FILE)
REG=$(env | grep AWS_REGION)
PROF=$(env | grep AWS_PROFILE)
[[ -z "$CRED" ]] && {
  echo "AWS_SHARED_CREDENTIALS_FILE environment variable is not set."
  exit 1
}
[[ -z "$REG" ]] && {
  echo "AWS_REGION environment variable is not set."
  exit 1
}
[[ -z "$PROF" ]] && {
  echo "AWS_PROFILE environment variable is not set."
  exit 1
}

# Read instance id strings from file.  [[ -n "$line" ]] handles the case where
# the last line doesn't end with a newline.
serverList=()
while IFS= read -r line || [[ -n "$line" ]]; do
  serverList+=("$line")
done < "$1"

if [ ${#serverList[@]} -eq 0 ]; then
  echo No instances found in "$1" - exiting.
  exit 1
fi

today=$(date +%Y-%m-%d)
logfile="$HOME/$today-ioc-scanner-hashscan.log"

# Suppress some verbose stdout.
# Suppress stderr of pkill command
exec > >(grep --invert-match 'Starting\|Exiting')
exec 2> >(grep --invert-match 'SIGTERM')

## FUNCTIONS
function getOSType() {
  OSNAME=$(aws ssm start-session --target="$i" \
    --document=AWS-StartInteractiveCommand \
    --parameters="command=cat /etc/os-release | grep --extended-regexp ^NAME=" \
    --output text)
  echo "$OSNAME" | grep NAME | cut -d'"' -f2 | cut -d' ' -f1
}

function getHost() {
  HOST=$(aws ssm start-session --target="$i" \
    --document=AWS-StartNonInteractiveCommand \
    --parameters="command=hostname" \
    --output text)
  echo "$HOST" | grep --invert-match "session" | sed '/^$/d'
}

function portForward() {
  aws ssm start-session --target="$i" \
    --document=AWS-StartPortForwardingSession --parameters="localPortNumber=5555,portNumber=6666"
}

function installNC() {
  if [[ "$OS" == "Debian" ]]; then
    aws ssm start-session --target="$i" \
      --document=AWS-StartInteractiveCommand \
      --parameters="command='sudo apt-get --yes install netcat'"
  else
    aws ssm start-session --target="$i" \
      --document=AWS-StartInteractiveCommand \
      --parameters="command='sudo dnf --assumeyes install netcat'"
  fi
}

function startListen() {
  if [[ "$OS" == "Debian" ]]; then
    aws ssm start-session --target="$i" \
      --document=AWS-StartInteractiveCommand \
      --parameters="command='cd ~/src/ioc_scan; nc -l -p 6666 | tar --extract --gzip --file -'"
  else
    aws ssm start-session --target="$i" \
      --document=AWS-StartInteractiveCommand \
      --parameters="command='cd ~/src/ioc_scan; nc -l 6666 | tar --extract --gzip --file -'"
  fi
}

function getSessionID() {
        SID=$(grep "Connection accepted for session" "$logfile" | tail --lines=1)
        echo "$SID" | cut -d'[' -f 2 | cut -d']' -f 1
}

## MAIN SCRIPT
echo "IOC Hash Scan - $today-$(date +%H:%M:%S)" > "$logfile"

for i in "${serverList[@]}"; do
  OS="$(getOSType)"
  if [[ "$OS" != "Debian" && "$OS" != "Fedora" ]]; then
    echo "Instance $i is running an operating system ($OS) that is not supported by this script."
    echo "Currently only Debian and Fedora are supported - exiting."
    exit 1
  fi

  instanceName=$(getHost)

  echo "Beginning scan of instance $i -- $instanceName" | tee -a "$logfile"

  # Start Port Forwarding
  echo "Beginning port forwarding (local port 5555 to remote port 6666)"
  portForward &

  # Create ~/src/ioc_scan directory on Instance
  echo "Verifying ~/src/ioc_scan directory on $instanceName"
  aws ssm start-session --target="$i" \
    --document=AWS-StartInteractiveCommand \
    --parameters="command='if [ ! -d ~/src/ioc_scan ]; then mkdir --parents ~/src/ioc_scan; fi'"

  #Install netcat and start listening on port 6666
  echo "Verifying netcat on $instanceName"
  installNC
  echo "Begin listening on $instanceName"
  startListen &

  # Copy latest ioc_scanner.py to target instance
  curdir=$(pwd)
  cd "$pydir" || exit

  echo "Upload lastest ioc_scanner.py to $instanceName"
  tar --create --gzip --file - ./ioc_scanner.py | nc localhost 5555

  cd "$curdir" || exit

  # Run ioc_scanner.py on target instance
  echo "Scan $instanceName for IOC Hashes"
  aws ssm start-session --target="$i" \
    --document=AWS-StartInteractiveCommand \
    --parameters="command=python3 ~/src/ioc_scan/ioc_scanner.py" >> "$logfile"

  # Terminate session so we can do this again on the next instance.
  id=$(getSessionID)
  aws ssm terminate-session --session-id="$id"

  echo "------------------------------------------------------------------------" | tee -a "$logfile"
done

##clean up log output for readability
while grep --quiet --ignore-case "session" "$logfile"; do
  sed -i '' '/session/d' "$logfile"
done

sed -i '' 'N;/^\n$/D;P;D;' "$logfile"

echo "Scan log may be found at: $logfile"
