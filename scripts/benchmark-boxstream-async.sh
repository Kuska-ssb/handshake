#!/bin/sh

set -ex

EXAMPLE="handshake-boxstream-bench-async"
ADDRESS="localhost:9999"
COUNTGB="4"

ARGS="--release --features sync --features async_std --example ${EXAMPLE}"

cargo build $ARGS

cargo run $ARGS server ${ADDRESS} $@ | \
    pv > /dev/null &

sleep 1

dd bs=1M count=$(echo "1024 * ${COUNTGB}" | bc) if=/dev/zero | \
    cargo run $ARGS client ${ADDRESS} $@ > /dev/null

pkill -P $$
