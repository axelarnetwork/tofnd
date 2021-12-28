#!/bin/bash

set -e

OK=0
ERR=1

# create: create a new mnemonic, export it to a file under the name "import" and continue
create_mnemonic() {
    echo "Creating mnemonic ..."

    # check if mnemonic path exists
    if [ -f "$TOFND_HOME/kvstore/kv/db" ]; then
        echo "Skipping create because a kv-store was found at $TOFND_HOME"
        return $ERR
    fi

    (echo ${PASSWORD} | tofnd ${ARGS} -m create) && mv $EXPORT_PATH $IMPORT_PATH && echo "... ok" && return $OK
    return $ERR
}

# import: import a mnemonic from $IMPORT_PATH and continue
import_mnemonic() {
    echo "Importing mnemonic ..."

    if [ -f "$TOFND_HOME/kvstore/kv/db" ]; then
        echo "Skipping import because a kv-store already exists at $TOFND_HOME"
        return $ERR
    fi

    if [ ! -f "$IMPORT_PATH" ]; then \
        echo "No import file found at $IMPORT_PATH"
        return $ERR
    fi

    if [ -n "${NOPASSWORD}" ]; then \
        echo "No password"
        (cat $IMPORT_PATH | tofnd ${ARGS} -m import) || return $ERR
    else
        echo "With password"
        ((echo $PASSWORD && cat $IMPORT_PATH) | tofnd ${ARGS} -m import) || return $ERR
    fi

    echo "... ok"
    return $OK
}

# export: export the mnemonic to $EXPORT_PATH, move it to $IMPORT_PATH and exit
export_mnemonic() {
    echo "Exporting mnemonic ..."
    echo ${PASSWORD} | tofnd ${ARGS} -m export && mv $EXPORT_PATH $IMPORT_PATH || return $ERR
    echo "... ok"
    return $OK
}

# Get password from env var
EMPTY_STRING=""
PASSWORD="${PASSWORD:-$EMPTY_STRING}"

# gather user's args
ARGS=""

# set tofnd root. TOFND_HOME can be set to a different path by the user.
TOFND_HOME=${TOFND_HOME:-"./.tofnd"}
IMPORT_PATH=$TOFND_HOME/import
EXPORT_PATH=$TOFND_HOME/export

echo "Using tofnd root:" $TOFND_HOME

# add '--no-password' and '--unsafe' flags to args if enabled
ARGS=${NOPASSWORD:+"${ARGS} --no-password"}
# add '--unsafe' flag to args if enabled
ARGS=${UNSAFE:+"${ARGS} --unsafe"}

# check mnemonic arg
if [ -n "${MNEMONIC_CMD}" ]; then \

    case ${MNEMONIC_CMD} in
        # auto: try to set up tofnd and then spin up tofnd with the existing mnemonic.
        # Order of set up: 1) import mnemonic, 2) create mnemonic.
        auto)
            echo "Trying import" && import_mnemonic \
            || (echo "... skipping. Trying to create" && create_mnemonic) \
            || echo "... skipping"
            ;;

        existing)
            ;;

        create)
            create_mnemonic || exit $ERR
            exit $OK
            ;;

        import)
            import_mnemonic || exit $ERR
            exit $OK
            ;;

        export)
            export_mnemonic || exit $ERR
            exit $OK
            ;;

        *)
            echo "Unknown command: ${MNEMONIC_CMD}"
            exit $ERR
            ;;
    esac

    echo "Using existing mnemonic ..."
    ARGS="${ARGS} -m existing"
fi

# execute tofnd daemon
exec echo ${PASSWORD} | tofnd ${ARGS} "$@"; \

