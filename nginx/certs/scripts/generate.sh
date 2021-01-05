#!/bin/bash

rm -rf generated
mkdir -p generated
cp {ca.pass,tls.pass,ca.conf,tls.conf} generated
cd generated

openssl genrsa -aes256 -out ca.key -passout file:ca.pass 4096
openssl req -new -x509 -sha256 -days 365 -utf8 -config ca.conf -key ca.key -passin file:ca.pass -out ca.crt

openssl genrsa -aes256 -out tls.key -passout file:tls.pass 4096
openssl req -new -sha256 -utf8 -config tls.conf -key tls.key -passin file:tls.pass -out tls.csr

mkdir -p ca.db.certs
echo '01' > ca.db.serial
cp /dev/null ca.db.index

openssl ca -batch -config ca.conf -passin file:ca.pass -out tls.crt -infiles tls.csr
openssl verify -CAfile ca.crt tls.crt

rm ca.db.serial.old
rm ca.db.index.old

cd ..
cp generated/{ca.crt,tls.pass,tls.key,tls.crt} ../

exit 0
