# Beside ESP-IDF: clang for libFuzzer and the sanitizers, clang-tidy, cppcheck,
# and OpenSSL for the host tests' SHA-256.
FROM espressif/idf:v6.1@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang-18 clang-tidy-18 libclang-rt-18-dev llvm-18 cppcheck libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/clang-18 /usr/local/bin/clang \
    && ln -sf /usr/bin/clang-tidy-18 /usr/local/bin/clang-tidy \
    && ln -sf /usr/bin/llvm-profdata-18 /usr/local/bin/llvm-profdata \
    && ln -sf /usr/bin/llvm-cov-18 /usr/local/bin/llvm-cov

# A venv of its own, so the dev tools never replace the esptool and friends
# ESP-IDF pins in its environment.
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN /opt/esp/python_env/idf6.1_py3.12_env/bin/python -m venv /opt/devtools \
    && /opt/devtools/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements-dev.txt
ENV PATH="${PATH}:/opt/devtools/bin"
