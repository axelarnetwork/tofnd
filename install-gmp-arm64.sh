#! /bin/bash

export HOMEBREW_NO_INSTALL_CLEANUP=TRUE
brew uninstall --ignore-dependencies gmp
ARM_DEPENDENCY=$(brew fetch --force --bottle-tag=arm64_big_sur gmp | grep Downloaded | awk '{print $3}')
brew install "$ARM_DEPENDENCY"