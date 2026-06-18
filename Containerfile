# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

ARG build_type
# Dependency build stage
FROM ghcr.io/trusted-execution-clusters/buildroot:fedora
ARG build_type
WORKDIR /build
RUN dnf -y update && dnf install --enablerepo='*debug*' -y install libstdc++-debuginfo openssl-libs-debuginfo libgcc-debuginfo glibc-debuginfo zlib-ng-compat-debuginfo systemd-libs-debuginfo libcap-debuginfo rust-gdb

COPY Makefile Cargo.toml Cargo.lock go.mod go.sum .
COPY api api
COPY lib lib
COPY operator/Cargo.toml operator/
COPY operator/src/lib.rs operator/src/

# Set only required crates as members to minimize rebuilds upon changes.
RUN sed -i 's/members = .*/members = ["lib", "operator"]/' Cargo.toml && \
    sed -i '/\[dev-dependencies\]/,$d' operator/Cargo.toml && \
    sed -i '/trusted-cluster-operator-test-utils/d' lib/Cargo.toml && \
    make crds-rs

# In debug builds, build dependencies to avoid full rebuild.
RUN if [ "$build_type" = debug ]; then cargo build -p operator; fi

# Target build stage
COPY operator/src operator/src
RUN cargo build -p operator $(if [ "$build_type" = release ]; then echo --release; fi) && \
    cp "/build/target/$build_type/operator" /usr/bin
