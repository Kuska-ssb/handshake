#!/bin/sh

set -ex

EXAMPLE="handshake-boxstream-bench"
ADDRESS="localhost:9999"
COUNTGB="4"

cargo build --release --example ${EXAMPLE}

cargo run --release --example ${EXAMPLE} server ${ADDRESS} $@ | \
    pv > /dev/null &

sleep 1

dd bs=1M count=$(echo "1024 * ${COUNTGB}" | bc) if=/dev/zero | \
    cargo run --release --example ${EXAMPLE} client ${ADDRESS} $@ > /dev/null

pkill -P $$
