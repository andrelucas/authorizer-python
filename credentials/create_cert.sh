#!/bin/bash

if ! builtin type -P openssl >/dev/null 2>&1; then
    echo "openssl command not found."
    exit 1
fi

function usage() {
    echo "Usage: $0 [-a <extension>] FILENAME CN" 2>&1
    exit 1
}

declare -a addext
while getopts ":a:p:" o; do
    case "${o}" in
        a)
            addext+=("${OPTARG}")
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

caconf=ca.conf
filebase="$1"
cn="$2"

if [[ -z "$cn" || -z "$filebase" ]]; then
    usage
fi

declare -a ext
for e in "${addext[@]}"; do
    ext+=("-addext")
    ext+=("$e")
done

echo "Will create a certificate for CN '${cn}' with base filename ${filebase}."
echo "Extensions: ${ext[*]}"
read -rp "Is this correct? (yes/no) " yn

case $yn in
    yes | y | Y | YES | Yes)
        ;;
	*)
        echo "Not proceeding"
        ;;
esac

set -e
set -x

openssl genrsa -out "${filebase}.key" 2048
openssl req -new -key "${filebase}.key" -out "${filebase}.csr" \
    -subj "/O=Akamai Inc/OU=Ceph Engineering/CN=${cn}" \
    "${ext[@]}"
openssl ca -config ${caconf} -verbose -in "${filebase}.csr" -out "${filebase}.crt"

