#!/bin/sh

set -ex

ADDRESS="localhost:9999"
COUNTGB="${COUNTGB:-4}"

MODE=$1

case "$MODE" in
    "sync")
        EXAMPLE="handshake-boxstream-bench-sync"
        ARGS="--release --features sync --example ${EXAMPLE}"
        ;;
    "async")
        EXAMPLE="handshake-boxstream-bench-async"
        ARGS="--release --features async_std --example ${EXAMPLE}"
        ;;
    *)
        printf "Usage: %s (sync/async) [--buf]\n" $0 1>&2
        exit 1
        ;;
esac

shift 1
OPTS=$@

cargo build $ARGS

cargo run $ARGS server ${ADDRESS} $@ | \
    pv -s ${COUNTGB}G > /dev/null &

sleep 1

dd bs=1M count=$(echo "1024 * ${COUNTGB}" | bc) if=/dev/zero | \
    cargo run $ARGS client ${ADDRESS} $@ > /dev/null

pkill -P $$
