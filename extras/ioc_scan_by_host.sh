#!/bin/bash
#
# Search for indicator of compromise (IOC) strings on a list of AWS instances
# via SSM.  The filename specified in the first argument (ioc-file)
# should contain a list of IOC strings, one per line.
#
# Usage: ./ioc_scan_by_host.sh ioc-file <instance-id>...

set -o nounset
set -o errexit
set -o pipefail

if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ $# -lt 2 ]; then
  echo Usage: "$0" ioc-file \<instance-id\>...
  exit 1
fi

# Check if IOC file exists.
if [ ! -f "$1" ]; then
  echo IOC file "$1" does not exist - exiting.
  exit 1
fi

# Read IOC strings from file.  [[ -n "$line" ]] handles the case where the last
# line doesn't end with a newline.
iocList=()
while IFS= read -r line || [[ -n "$line" ]]; do
  iocList+=("$line")
done < "$1"

if [ ${#iocList[@]} -eq 0 ]; then
  echo No IOCs found in "$1" - exiting.
  exit 1
fi

today=$(date +%Y%m%d)
logfile="./$today-ioc-scan.log"
# tee -a: Append to existing logfile
# tee -i: Ignore SIGINT signals
exec > >(tee -ai "$logfile")
exec 2> >(tee -ai "$logfile" >&2)

# Get list of arguments passed to script, but ignore the first two (script name
# and IOC file); the rest are the instance IDs.
instances=("${@:2}")

echo IOC List is: "${iocList[*]}"
echo Instances are: "${instances[*]}"

# Loop through all instance IDs
for instance_id in "${instances[@]}"; do
  # "echo -e" allows us to use \n for newlines.
  echo -e "\nSearching $instance_id:"

  # Use grep to search for IOC strings in log files.  We use the --invert-match
  # grep flag to exclude files that contain our grep command (e.g. sudo.log) and
  # also to exclude .journal file matches.
  aws ssm start-session --target="$instance_id" \
    --document=AWS-StartInteractiveCommand \
    --parameters="command='for i in ${iocList[*]}; do sudo grep --ignore-case --recursive --extended-regexp \$i /var/log/* | grep --invert-match ignore-case | grep  --invert-match .journal | echo \$(wc --lines) found for \$i; done'"

  echo Search of "$instance_id" is complete.
done
