#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 tpm2-tss contributors
# SPDX-License-Identifier: BSD-2-Clause
#
# Run tpm2-tss PQC integration tests against wolfTPM fwTPM.
# Exit 0 on pass, 77 if fwTPM unavailable (SKIP), non-zero on failure.

set -euo pipefail

FWTPM_PORT="${FWTPM_PORT:-2321}"
FWTPM_HOST="${FWTPM_HOST:-127.0.0.1}"
FWTPM_BIN="${FWTPM_BIN:-/code/spdm/wolfTPM/src/fwtpm/fwtpm_server}"
FWTPM_WOLFTPM_DIR="${FWTPM_WOLFTPM_DIR:-/code/spdm/wolfTPM}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

TCTI="mssim:host=${FWTPM_HOST},port=${FWTPM_PORT}"
PID_FILE="${TMPDIR:-/tmp}/fwtpm_server_${FWTPM_PORT}.pid"
LOG_FILE="${TMPDIR:-/tmp}/fwtpm_server_${FWTPM_PORT}.log"
STARTED_BY_SCRIPT=0

ESYS_TESTS=(
    esys-encapsulate
    esys-sign-digest
    esys-sign-sequence
    esys-sign-deprecated
    esys-get-capability-pqc
    esys-mldsa87-buffer
    esys-quote-mldsa
    esys-mlkem-session
    sys-encapsulate
    sys-sign-digest
    sys-sign-sequence
)

FAPI_TESTS=(
    fapi-key-create-mldsa
    fapi-key-create-mldsa-sequence
    fapi-key-create-mlkem
    fapi-quote-mldsa
)

fwtpm_listening() {
    ss -lntp4 2>/dev/null | grep -q ":${FWTPM_PORT} "
}

resolve_fwtpm_bin() {
    if [[ -x "${FWTPM_BIN}" ]]; then
        return 0
    fi
    local candidate="${FWTPM_WOLFTPM_DIR}/src/fwtpm/fwtpm_server"
    if [[ -x "${candidate}" ]]; then
        FWTPM_BIN="${candidate}"
        return 0
    fi
    return 1
}

start_fwtpm() {
    if ! resolve_fwtpm_bin; then
        echo "run-fwtpm-tests: fwTPM binary not found (set FWTPM_BIN or build wolfTPM)" >&2
        return 77
    fi

    "${FWTPM_BIN}" --port "${FWTPM_PORT}" --clear >"${LOG_FILE}" 2>&1 &
    local pid=$!
    echo "${pid}" >"${PID_FILE}"
    STARTED_BY_SCRIPT=1

    for _ in $(seq 1 20); do
        if fwtpm_listening; then
            echo "run-fwtpm-tests: started ${FWTPM_BIN} on port ${FWTPM_PORT} (pid ${pid})"
            return 0
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "run-fwtpm-tests: fwtpm_server exited early; see ${LOG_FILE}" >&2
            tail -20 "${LOG_FILE}" >&2 || true
            return 77
        fi
        sleep 0.25
    done

    echo "run-fwtpm-tests: fwtpm_server did not bind to port ${FWTPM_PORT}" >&2
    return 77
}

stop_fwtpm() {
    if [[ "${STARTED_BY_SCRIPT}" -eq 0 ]]; then
        return 0
    fi
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
        rm -f "${PID_FILE}"
    fi
}

setup_ld_library_path() {
    local dirs=(
        "${TSS_ROOT}/src/tss2-mu/.libs"
        "${TSS_ROOT}/src/tss2-tcti/.libs"
        "${TSS_ROOT}/src/tss2-sys/.libs"
        "${TSS_ROOT}/src/tss2-esys/.libs"
        "${TSS_ROOT}/src/tss2-rc/.libs"
        "${TSS_ROOT}/src/tss2-fapi/.libs"
        "${TSS_ROOT}/src/tss2-policy/.libs"
    )
    local path=""
    for d in "${dirs[@]}"; do
        if [[ -d "${d}" ]]; then
            path="${d}:${path}"
        fi
    done
    if [[ -z "${path}" ]]; then
        echo "run-fwtpm-tests: tpm2-tss not built (missing .libs under ${TSS_ROOT})" >&2
        return 1
    fi
    export LD_LIBRARY_PATH="${path}${LD_LIBRARY_PATH:-}"
}

run_test() {
    local ext=$1
    local name=$2
    local bin="${TSS_ROOT}/test/integration/.libs/${name}.${ext}"

    if [[ ! -x "${bin}" ]]; then
        echo "run-fwtpm-tests: missing ${bin} (run make in ${TSS_ROOT})" >&2
        exit 1
    fi
    echo "=== ${name} ==="
    if env TPM20TEST_TCTI="${TCTI}" "${bin}"; then
        echo "${name}: PASS"
    else
        local trc=$?
        if [[ "${trc}" -eq 77 ]]; then
            echo "${name}: SKIP (exit 77 — TPM lacks PQC; is fwTPM running with --enable-pqc?)" >&2
            exit 77
        fi
        echo "${name}: FAIL (exit ${trc})" >&2
        return 1
    fi
    return 0
}

main() {
    trap stop_fwtpm EXIT

    if fwtpm_listening; then
        echo "run-fwtpm-tests: fwTPM already listening on ${FWTPM_HOST}:${FWTPM_PORT}"
    else
        local rc=0
        start_fwtpm || rc=$?
        if [[ "${rc}" -eq 77 ]]; then
            exit 77
        fi
        if [[ "${rc}" -ne 0 ]]; then
            exit "${rc}"
        fi
    fi

    setup_ld_library_path || exit 1

    local failed=0
    for t in "${ESYS_TESTS[@]}"; do
        run_test int "${t}" || failed=1
    done
    for t in "${FAPI_TESTS[@]}"; do
        run_test fint "${t}" || failed=1
    done

    if [[ "${failed}" -ne 0 ]]; then
        exit 1
    fi

    echo "run-fwtpm-tests: all PQC integration tests passed"
    exit 0
}

main "$@"
