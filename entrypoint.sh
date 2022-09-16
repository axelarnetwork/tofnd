#!/bin/bash

set -e

OK=0
ERR=1

# create: create a new mnemonic and export it to $EXPORT_PATH
create_mnemonic() {
    echo "Creating mnemonic ..."

    # check if mnemonic path exists
    if [ -f "$TOFND_HOME/kvstore/kv/db" ]; then
        echo "Skipping create because a kv-store was found at $TOFND_HOME"
        return $ERR
    fi

    (echo "${PASSWORD}" | tofnd "${ARGS[@]}" -m create) && echo "... ok" && return $OK
    return $ERR
}

rotate_mnemonic() {
  if [ -a "$ROTATE_PATH" ]; then
    echo "File found at $ROTATE_PATH. Attempting to rotate mnemonic"

    if [ -a "$IMPORT_PATH" ]; then
      timestamp=$(date +%Y-%m-%d-%m)
      backup_path="$IMPORT_PATH-$timestamp.bak"
      mv "$IMPORT_PATH" "$backup_path"
      echo "Warning: Previous import file found. Delete $backup_path file after backing up."
    fi

    if [ -n "${NOPASSWORD}" ]; then \
        echo "Rotating without password"
        (tofnd "${ARGS[@]}" -m rotate) || return $ERR
    else
        echo "Rotating with password"
        (echo "$PASSWORD" | tofnd "${ARGS[@]}" -m rotate) || return $ERR
    fi
    printf "\n\n"
    mv "$EXPORT_PATH" "$IMPORT_PATH"
    rm "$ROTATE_PATH"
  else
    echo "Mnemonic rotation skipped. No file found at $ROTATE_PATH"
  fi
  return $OK
}

# import: import a mnemonic from $IMPORT_PATH
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
        (tofnd "${ARGS[@]}" -m import < "$IMPORT_PATH") || return $ERR
    else
        echo "With password"
        ( (echo "$PASSWORD" && cat "$IMPORT_PATH") | tofnd "${ARGS[@]}" -m import) || return $ERR
    fi

    echo "... ok"
    return $OK
}

# export: export the mnemonic to $EXPORT_PATH
export_mnemonic() {
    echo "Exporting mnemonic ..."
    echo "${PASSWORD}" | tofnd "${ARGS[@]}" -m export || return $ERR
    echo "... ok"
    return $OK
}

# Get password from env var
EMPTY_STRING=""
PASSWORD="${PASSWORD:-$EMPTY_STRING}"

# set tofnd root. TOFND_HOME can be set to a different path by the user.
TOFND_HOME=${TOFND_HOME:-"./.tofnd"}
IMPORT_PATH=$TOFND_HOME/import
EXPORT_PATH=$TOFND_HOME/export
ROTATE_PATH=$TOFND_HOME/rotate

echo "Using tofnd root:" "$TOFND_HOME"

# gather user's args

ARGS=()
# add '--no-password' and '--unsafe' flags to args if enabled
if [ -n "$NOPASSWORD" ]; then ARGS+=("--no-password"); fi

# add '--unsafe' flag to args if enabled
if [ -n "$UNSAFE" ]; then ARGS+=("--unsafe"); fi

# # add '--address' flag to args if enabled
if [ -n "$ADDRESS" ]; then ARGS+=("--address" "$ADDRESS"); fi

# # add '--port' flag to args if enabled
if [ -n "$PORT" ]; then ARGS+=("--port" "$PORT"); fi

# check mnemonic arg
if [ -n "${MNEMONIC_CMD}" ]; then \

    case ${MNEMONIC_CMD} in
        # auto: try to set up tofnd and then spin up tofnd with the existing mnemonic.
        # Order of set up: 1) import mnemonic, 2) create mnemonic.
        # If 2) then move the mnemonic to $IMPORT_PATH so that tofnd will not complain
        auto)
            echo "Trying to import mnemonic" && import_mnemonic \
            || (echo "Unable to import mnemonic. Trying to create mnemonic" && create_mnemonic && mv "$EXPORT_PATH" "$IMPORT_PATH") \
            || rotate_mnemonic && echo "Proceeding without creating or importing mnemonic. Using existing mnemonic"
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
    ARGS+=("-m" "existing")
fi

# execute tofnd daemon
exec echo "${PASSWORD}" | tofnd "${ARGS[@]}" "$@"; \

