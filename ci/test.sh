#! /usr/bin/env bash

# It's possible to use this script locally from the zeek repo's root dir.
# The parallelism level when running tests locally is $1 if provided, else
# the value of `nproc` if available, otherwise just a single core.

result=0
BTEST=$(pwd)/auxil/btest/btest

if [[ -z "${CIRRUS_CI}" ]]; then
    # Set default values to use in place of env. variables set by Cirrus CI.
    ZEEK_CI_CPUS=1
    [[ $(which nproc) ]] && ZEEK_CI_CPUS=$(nproc)
    [[ -n "${1}" ]] && ZEEK_CI_CPUS=${1}
    ZEEK_CI_BTEST_JOBS=${ZEEK_CI_CPUS}
    ZEEK_CI_BTEST_RETRIES=2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
. ${SCRIPT_DIR}/common.sh

function pushd
    {
    command pushd "$@" > /dev/null || exit 1
    }

function popd
    {
    command popd "$@" > /dev/null || exit 1
    }

function banner
    {
    local msg="${1}"
    printf "+--------------------------------------------------------------+\n"
    printf "| %-60s |\n" "$(date)"
    printf "| %-60s |\n" "${msg}"
    printf "+--------------------------------------------------------------+\n"
    }

function run_unit_tests
    {
    banner "Running unit tests"

    pushd build
    ( . ./zeek-path-dev.sh && zeek --test ) || result=1
    popd
    return 0
    }

function prep_artifacts
    {
    banner "Prepare artifacts"
    [[ -d .tmp ]] && rm -rf .tmp/script-coverage && tar -czf tmp.tar.gz .tmp
    junit2html btest-results.xml btest-results.html
    }

function run_btests
    {
    banner "Running baseline tests: zeek"

    pushd testing/btest
    ${BTEST} -d -b -x btest-results.xml -j ${ZEEK_CI_BTEST_JOBS} || result=1
    make coverage
    prep_artifacts
    popd
    return 0
    }

banner "Start tests: ${ZEEK_CI_CPUS} cpus, ${ZEEK_CI_BTEST_JOBS} btest jobs"

run_unit_tests
run_btests

exit ${result}
