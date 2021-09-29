#!/bin/bash

set -e

# TODO: get actual password from user. See https://github.com/axelarnetwork/axelarate/issues/269.
PASSWORD=""

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
        # existing: continues using the existing mnemonic. 
        existing)
            echo "Using existing mnemonic"
            ;;

        # create: create a new mnemonic, export it to a file, and save it under name "import" and continues
        create)
            echo "Creating new mnemonic"
            echo ${PASSWORD} | tofnd ${ARGS} -m create && mv $EXPORT_PATH $IMPORT_PATH || exit 1
            ;;

        # import: import a mnemonic from import path and continues
        import)
            echo "Importing mnemonic"

            # check if import file exists
            [ -f $IMPORT_PATH ] || (echo "No import file found at $IMPORT_PATH" && exit 1)

            # check if password exists
            if [ -n "${NOPASSWORD}" ]; then \
                echo "No password"
                (cat $IMPORT_PATH | tofnd ${ARGS} -m import) || exit 1
            else
                echo "With password"
                # TODO: provide actual password here
                ((echo $PASSWORD && cat $IMPORT_PATH) | tofnd ${ARGS} -m import) || exit 1
            fi
            ;;

        # export: exports the mnemonic to import file and exits
        export)
            echo "Exporting mnemonic"
            echo ${PASSWORD} | tofnd ${ARGS} -m export && mv $EXPORT_PATH $IMPORT_PATH
            exit
            ;;

        *)
            echo "Unknown command: ${MNEMONIC_CMD}"
            exit 1
            ;;
    esac

    ARGS="${ARGS} -m existing"
fi

# execute tofnd daemon
exec echo ${PASSWORD} | tofnd ${ARGS} "$@"; \
