#! /usr/bin/env bash
#
# Cmake invokes this at installation time, so normally outside of the
# source tree. Therefore we need to know where this script is located
# so it can rely on other files co-located with it.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -e

if [ -n "$1" ]; then
    PATH="$PATH:$1"
fi

if [ -n "$2" ]; then
    VERSION="--version $2"
fi

if type -P zeek-config; then
    zkg autoconfig
fi

zkg --config $DIR/zkg-config.ini install --force --skiptests $VERSION zeek-packages/zeek-package-collection
zkg list
