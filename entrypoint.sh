#!/bin/bash

set -e

ARGS=""
if [ -n "${UNSAFE}" ]; then \
    ARGS="$ARGS --unsafe"; \
fi
if [ -n "${MNEMONIC_CMD}" ]; then \
    ARGS="$ARGS -m $MNEMONIC_CMD"; \
fi
exec tofnd $ARGS "$@"; \
