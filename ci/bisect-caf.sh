#! /usr/bin/env bash

top=$(pwd)

cd auxil/broker/caf

git bisect start
git bisect bad
git bisect good 0.18.3

git bisect run $top/ci/bisect-check.sh $top
