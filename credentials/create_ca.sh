#!/bin/bash

if ! builtin type -P openssl >/dev/null 2>&1; then
    echo "openssl command not found."
    exit 1
fi

scriptdir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cadir="$scriptdir"
cacrtconf=cacrt.conf
caconf=ca.conf

if [[ -f ${caconf} ]]; then
    echo "CA already initialized."
    exit 1
fi

sed -e "s#@@PWD@@#${cadir}#g" ${caconf}.in > ${caconf}

set -e
set -x

openssl genrsa -out root.key 4096
chmod 0600 root.key
openssl req -new -x509 -days 730 -key root.key -out root.crt -config ${cacrtconf}

set +x

mkdir -p certs # database of signed certificates
touch index # index of signed certificates
dd if=/dev/urandom of=random bs=256 count=1
echo "01" > serial # Initialize the serial number for numbering certificates
echo "01" > crlnumber # Initialize the serial number for numbering revokation lists (CRLs)
