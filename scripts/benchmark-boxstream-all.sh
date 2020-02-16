#!/bin/bash

set -e

SCRIPTPATH=`dirname $0`

export COUNTGB=4

run() {
    # result=$( $1 2>&1 | tee >(cat - >&2))
    printf "Running $1\n" 1>&2
    result=$( $1 2>&1 )
    speed=$(echo $result | grep -Po "[.0-9]* .?B/s")
}


cpu=$(cat /proc/cpuinfo  | grep -P -o "(?<=model name\t: ).*" | head -n1)
kernel=$(uname -srm)
rustver=$(rustc --version)
commit=$(git log --format="%H" -n 1)

run "${SCRIPTPATH}/benchmark-boxstream.sh sync"
speed_sync="$speed"
run "${SCRIPTPATH}/benchmark-boxstream.sh sync --buf"
speed_sync_buf="$speed"
run "${SCRIPTPATH}/benchmark-boxstream.sh async"
speed_async="$speed"
run "${SCRIPTPATH}/benchmark-boxstream.sh async --buf"
speed_async_buf="$speed"

printf "## $(date)\n"

printf -- "- cpu: $cpu\n"
printf -- "- kernel: $kernel\n"
printf -- "- rust version: $rustver\n"
printf -- "- commit: $commit\n"

printf " | mode  | unbuffered   | buffered         |\n"
printf " | ----- | ------------ | ---------------- |\n"
printf " | sync  | $speed_sync  | $speed_sync_buf  |\n"
printf " | async | $speed_async | $speed_async_buf |\n"
