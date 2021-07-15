#! /usr/bin/env bash

top=$1

cd $top

./ci/build.sh || exit 1
./ci/test.sh || exit 1

exit 0
