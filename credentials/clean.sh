#!/bin/bash

read -rp "Delete all CA files and start again? (yes/no) " yn

case $yn in
    yes | y | Y | YES | Yes)
        ;;
	*)
        echo "Not proceeding"
        ;;
esac

rm -rf certs
rm -f crlnumber index index.attr index.old random serial serial.old
rm -f root.crt root.key
rm -f ca.conf
rm -f -- *.crt *.csr *.key
