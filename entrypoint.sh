#!/bin/bash

# usage:
# $ docker-compose up
# or
# $ docker-compose run -e MNEMONIC_CMD=<mnemonic_cmd> tofnd

set -e

# TODO: get actual password from user. See https://github.com/axelarnetwork/axelarate/issues/269.
PASSWORD=""

# gather user's args
ARGS=""

# add '--no-password' flag to args
if [ -n "${NOPASSWORD}" ]; then \
    ARGS="${ARGS} --no-password"; \
fi

# add '--unsafe' flag to args
if [ -n "${UNSAFE}" ]; then \
    ARGS="${ARGS} --unsafe"; \
fi

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
            echo ${PASSWORD} | tofnd ${ARGS} -m create && mv /.tofnd/export /.tofnd/import || exit 1
            ;;

        # import: import a mnemonic from "./.tofnd/import" and continues
        import)
            echo "Importing mnemonic"

            # check if import file exists
            [ -f /.tofnd/import ] || (echo "No import file found at /.tofnd/import" && exit 1)

            # check if import file exists
            if [ -n "${NOPASSWORD}" ]; then \
                echo "No password"
                (cat /.tofnd/import | tofnd ${ARGS} -m import) || exit 1
            else
                echo "With password"
                # TODO: provide actual password here
                ((echo $PASSWORD && cat /.tofnd/import) | tofnd ${ARGS} -m import) || exit 1
            fi
            ;;

        # export: exports the mnemonic to "./.tofnd/import" file and exits
        export)
            echo "Exporting mnemonic"
            echo ${PASSWORD} | tofnd ${ARGS} -m export && mv /.tofnd/export /.tofnd/import
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
