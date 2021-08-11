#!/bin/bash

set -e

if [ -n "${UNSAFE}" ]; then \
    exec tofnd --unsafe "$@"; \
else \
    exec tofnd "$@"; \
fi
