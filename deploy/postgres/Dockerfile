# syntax=docker/dockerfile:1.7

FROM postgres:18.4-bookworm AS validator-build
# PostgreSQL's OAuth server header includes pg-gssapi.h, so the matching
# Kerberos headers are a compile-time dependency even though this spike does
# not perform GSSAPI authentication.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libjansson-dev \
        libkrb5-dev \
        libssl-dev \
        postgresql-server-dev-18 \
    && rm -rf /var/lib/apt/lists/*
COPY spikes/postgres-oauth/validator /src/validator
RUN make -C /src/validator \
    && make -C /src/validator DESTDIR=/out install

FROM postgres:18.4-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends libjansson4 libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=validator-build \
    /out/usr/lib/postgresql/18/lib/custody_jwt_validator.so \
    /usr/lib/postgresql/18/lib/custody_jwt_validator.so
COPY --chmod=0755 deploy/postgres/init-oauth.sh /docker-entrypoint-initdb.d/10-init-oauth.sh
