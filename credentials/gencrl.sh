#!/bin/bash

if ! builtin type -P openssl >/dev/null 2>&1; then
    echo "openssl command not found."
    exit 1
fi

crlfile=root.crl
echo "Will write updated CRL to ${crlfile}."

set -x
openssl ca -config ca.conf -gencrl -out "${crlfile}"
