#!/bin/bash

if ! builtin type -P openssl >/dev/null 2>&1; then
    echo "openssl command not found."
    exit 1
fi

function usage() {
    echo "Usage: $0 CERT-FILE-TO_REVOKE" 2>&1
    exit 1
}

caconf=ca.conf

openssl ca -config ${caconf} -revoke "$1"
