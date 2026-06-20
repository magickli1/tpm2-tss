fwTPM PQC integration tests
===========================

These tests exercise v185 PQC commands (ML-KEM, ML-DSA) against wolfTPM
fwTPM over the mssim socket transport. They SKIP (exit 77) when the TPM
does not advertise PQC algorithms — for example the default `make check`
harness with swtpm. That SKIP is expected and must not fail the suite.

Why `make check` alone is not enough
-----------------------------------

The integration harness (`script/int-log-compiler.sh`) reads
**configure-time** `INTEGRATION_TCTI` (often empty or swtpm), not
`TPM20TEST_TCTI` on the make command line. When `INTEGRATION_TCTI`
contains `mssim`, the harness also tries to start IBM `tpm_server`, not
wolfTPM `fwtpm_server`. PQC tests therefore need a pre-started fwTPM and
either direct `.int` execution or the helper script below.

Prerequisites — wolfSSL + wolfTPM fwTPM
---------------------------------------

Distro `libwolfssl-dev` (e.g. 5.6.x) lacks ML-DSA symbols required for
PQC. Build wolfSSL from source with wolfTPM-compatible flags, then point
wolfTPM at it.

Build wolfSSL (PQC + fwTPM crypto):

    cd /code/spdm
    git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
    cd wolfssl
    ./autogen.sh
    ./configure --prefix=/usr/local \
        --enable-wolftpm --enable-pkcallbacks --enable-keygen \
        --enable-dilithium --enable-mlkem --enable-experimental --enable-harden \
        CFLAGS="-DWC_RSA_NO_PADDING"
    make -j$(nproc)
    sudo make install
    sudo ldconfig

Build wolfTPM fwTPM:

    cd /code/spdm/wolfTPM
    ./configure --enable-fwtpm --enable-pqc --with-wolfssl=/usr/local
    make -j$(nproc)

Binary: `/code/spdm/wolfTPM/src/fwtpm/fwtpm_server` (needs `WOLFTPM_V185`).

Start fwTPM (default mssim port 2321):

    /code/spdm/wolfTPM/src/fwtpm/fwtpm_server --port 2321 --clear

Or use the upstream harness:

    cd /code/spdm/wolfTPM && ./tests/pqc_mssim_e2e.sh

Build tpm2-tss integration tests
--------------------------------

    cd /code/tpm2-tss
    ./configure --enable-unit --enable-integration --enable-fapi --disable-policy
    make -j$(nproc)

Run directly (recommended)
--------------------------

Bypasses `int-log-compiler.sh`. fwTPM must already be listening on port
2321. Set `LD_LIBRARY_PATH` to in-tree `.libs` and `TPM20TEST_TCTI` to
the mssim socket:

    cd /code/tpm2-tss
    export LD_LIBRARY_PATH="/code/tpm2-tss/src/tss2-mu/.libs:/code/tpm2-tss/src/tss2-tcti/.libs:/code/tpm2-tss/src/tss2-sys/.libs:/code/tpm2-tss/src/tss2-esys/.libs:/code/tpm2-tss/src/tss2-rc/.libs:${LD_LIBRARY_PATH:-}"
    export TPM20TEST_TCTI="mssim:host=127.0.0.1,port=2321"

    ./test/integration/.libs/esys-encapsulate.int
    ./test/integration/.libs/esys-sign-digest.int
    ./test/integration/.libs/esys-sign-sequence.int
    ./test/integration/.libs/sys-encapsulate.int

Or use the helper script (starts fwTPM if missing, same env):

    ./test/integration/pqc-fwtpm/run-fwtpm-tests.sh

Run via `make check` (fwTPM pre-started)
----------------------------------------

Start `fwtpm_server` on 2321 first, then override the harness TCTI.
Prefer the helper script for the full matrix:

    ./test/integration/pqc-fwtpm/run-fwtpm-tests.sh

Or limit `make check` to a subset, for example:

    cd /code/tpm2-tss
    make check \
        INTEGRATION_TCTI='mssim:host=127.0.0.1,port=2321' \
        TESTS="test/integration/esys-encapsulate test/integration/esys-sign-digest test/integration/esys-sign-sequence test/integration/sys-encapsulate"

Note: if `tpm_server` is not on `PATH`, the harness may still fail while
trying to start a simulator even though fwTPM is already on 2321. Prefer
`run-fwtpm-tests.sh` or direct `.int` invocation in that case.

Default `make check` / swtpm behavior
-------------------------------------

With swtpm or no v185 TPM, each PQC test exits **77** (SKIP). Autotools
treats exit 77 as success for optional tests — this is expected until
swtpm gains v185 PQC support.

Covered tests
-------------

ESYS/SYS (via `run-fwtpm-tests.sh` or direct `.int` execution):

- `test/integration/esys-encapsulate.int`
- `test/integration/esys-sign-digest.int`
- `test/integration/esys-sign-sequence.int`
- `test/integration/esys-sign-deprecated.int`
- `test/integration/esys-get-capability-pqc.int`
- `test/integration/esys-mldsa87-buffer.int`
- `test/integration/esys-quote-mldsa.int`
- `test/integration/esys-mlkem-session.int`
- `test/integration/sys-encapsulate.int`
- `test/integration/sys-sign-digest.int`
- `test/integration/sys-sign-sequence.int`

FAPI (`--enable-fapi`, profiles `P_MLDSA` / `P_MLDSA_SIGN` / `P_MLKEM`):

- `test/integration/fapi-key-create-mldsa.fint`
- `test/integration/fapi-key-create-mldsa-sequence.fint`
- `test/integration/fapi-key-create-mlkem.fint`
- `test/integration/fapi-quote-mldsa.fint`

Assertions (wolfTPM oracle):

- ML-KEM-768: ciphertext 1088 bytes, shared secret 32 bytes, encap/decap match
- HashMLDSA-65 SignDigest: signature 3309 bytes, ticket TPM2_ST_DIGEST_VERIFIED
- Pure MLDSA-65 SignSequence: signature 3309 bytes, ticket TPM2_ST_MESSAGE_VERIFIED

Reference: `/code/spdm/wolfTPM/examples/pqc/pqc_mssim_e2e.c`
