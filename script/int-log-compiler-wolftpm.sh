#!/usr/bin/env bash
#;**********************************************************************;
# SPDX-License-Identifier: BSD-2-Clause
#
# Integration test log compiler for wolfTPM fwTPM (mssim socket transport).
#
# Starts fwtpm_server, points TPM20TEST_TCTI at tcti-mssim, runs the test
# binary, then tears down the server.
#
# Environment:
#   FWTPM_SERVER       - path to fwtpm_server (default: search PATH, then
#                        $FWTPM_SRC/src/fwtpm/fwtpm_server)
#   FWTPM_SRC          - wolfTPM source tree (default: none)
#   FWTPM_PORT         - command port (default: 2321)
#   FWTPM_USE_EXISTING - if set, connect to an already-running server on
#                        FWTPM_PORT instead of starting a new one
#;**********************************************************************;

set -u

usage_error() {
    echo "$0: $*" >&2
    print_usage >&2
    exit 2
}

print_usage() {
    cat <<END
Usage:
    $(basename "$0") TEST-SCRIPT [TEST-SCRIPT-ARGUMENTS]
END
}

while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $? ;;
    --) shift; break ;;
    -*) usage_error "invalid option: '$1'" ;;
    *) break ;;
    esac
    shift
done

if [ $# -lt 1 ]; then
    usage_error "missing test script"
fi

TEST_BIN=$(realpath "${@: -1}")
TEST_DIR=$(dirname "${@: -1}")
SIM_LOG_FILE="${TEST_BIN}_fwtpm_server.log"
SIM_PID_FILE="${TEST_BIN}_fwtpm_server.pid"
SIM_TMP_DIR=$(mktemp -d /tmp/fwtpm_simulator_XXXXXX)

# WOLFTPM_FWSERVER is an alias for FWTPM_SERVER (documentation compatibility)
FWTPM_SERVER="${FWTPM_SERVER:-${WOLFTPM_FWSERVER:-}}"

find_fwtpm_server() {
    if [ -n "${FWTPM_SERVER:-}" ] && [ -x "${FWTPM_SERVER}" ]; then
        echo "${FWTPM_SERVER}"
        return 0
    fi
    if command -v fwtpm_server >/dev/null 2>&1; then
        command -v fwtpm_server
        return 0
    fi
    for candidate in "${HOME}/tpm/wolfTPM/src/fwtpm/fwtpm_server" "${HOME}/tpm/wolfTPM/.libs/fwtpm_server"; do
        if [ -x "${candidate}" ]; then
            echo "${candidate}"
            return 0
        fi
    done
    if [ -n "${FWTPM_SRC:-}" ] && [ -x "${FWTPM_SRC}/src/fwtpm/fwtpm_server" ]; then
        echo "${FWTPM_SRC}/src/fwtpm/fwtpm_server"
        return 0
    fi
    return 1
}

SIM_PORT_DATA=${FWTPM_PORT:-2321}

if [ -z "${FWTPM_USE_EXISTING:-}" ] && exec 3<>/dev/tcp/127.0.0.1/${SIM_PORT_DATA} 2>/dev/null; then
    exec 3>&-
    FWTPM_USE_EXISTING=1
fi

FWTPM_BIN=$(find_fwtpm_server) || {
    if [ -n "${FWTPM_USE_EXISTING:-}" ]; then
        FWTPM_BIN="(already running)"
    else
        echo "SKIP: fwtpm_server not found (set FWTPM_SERVER or FWTPM_SRC)" >&2
        rm -rf "${SIM_TMP_DIR}"
        exit 77
    fi
}

if [ -n "${FWTPM_USE_EXISTING:-}" ]; then
    if ! exec 3<>/dev/tcp/127.0.0.1/${SIM_PORT_DATA}; then
        echo "FAIL: no fwTPM listener on 127.0.0.1:${SIM_PORT_DATA}" >&2
        rm -rf "${SIM_TMP_DIR}"
        exit 1
    fi
    exec 3>&-
    TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}"
    echo "Using existing fwTPM on port ${SIM_PORT_DATA}"
    echo "TPM20TEST_TCTI=${TPM20TEST_TCTI}"
    echo "Execute the test script"
    env TPM20TEST_TCTI="${TPM20TEST_TCTI}" \
        FWTPM_SKIP_STATE_CHECKS=1 \
        G_MESSAGES_DEBUG=all \
        "${@: -1}"
    exit $?
fi

PORT_MIN=1024
PORT_MAX=65534
for _ in 1 2 3 4 5 6 7 8 9 10; do
    SIM_PORT_DATA=$(od -A n -N 2 -t u2 /dev/urandom | awk -v min=${PORT_MIN} -v max=${PORT_MAX} '{print ($1 % (max - min)) + min}')
    if [ $(expr ${SIM_PORT_DATA} % 2) -eq 1 ]; then
        SIM_PORT_DATA=$((${SIM_PORT_DATA} - 1))
    fi
    SIM_PORT_PLATFORM=$((${SIM_PORT_DATA} + 1))
    FWTPM_NV_FILE="${SIM_TMP_DIR}/nvchip.bin"
    echo "Starting ${FWTPM_BIN} on port ${SIM_PORT_DATA}"
    FWTPM_NV_FILE="${FWTPM_NV_FILE}" "${FWTPM_BIN}" \
        --port "${SIM_PORT_DATA}" --platform-port "${SIM_PORT_PLATFORM}" --clear \
        >"${SIM_LOG_FILE}" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "fwtpm_server died during startup; see ${SIM_LOG_FILE}" >&2
        tail -20 "${SIM_LOG_FILE}" >&2
        continue
    fi
    if exec 3<>/dev/tcp/127.0.0.1/${SIM_PORT_DATA}; then
        exec 3>&-
        echo "${SERVER_PID}" >"${SIM_PID_FILE}"
        break
    fi
    kill "${SERVER_PID}" 2>/dev/null || true
done

if [ ! -s "${SIM_PID_FILE:-}" ]; then
    echo "FAIL: could not start fwtpm_server" >&2
    rm -rf "${SIM_TMP_DIR}"
    exit 1
fi

SERVER_PID=$(cat "${SIM_PID_FILE}")
TPM20TEST_TCTI="mssim:host=127.0.0.1,port=${SIM_PORT_DATA}"

echo "FWTPM_SERVER=${FWTPM_BIN}"
echo "TPM20TEST_TCTI=${TPM20TEST_TCTI}"

echo "Execute the test script"
env TPM20TEST_TCTI="${TPM20TEST_TCTI}" \
    FWTPM_SKIP_STATE_CHECKS=1 \
    G_MESSAGES_DEBUG=all \
    "${@: -1}"
ret=$?
echo "Script returned $ret"

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true
rm -rf "${SIM_TMP_DIR}" "${SIM_PID_FILE}"

exit $ret
