#!/bin/bash

set -e

openssl genrsa -out ca.key 4096\n
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 \
    -days 3650 \
    -out ca.crt \
    -subj "/C=TR/O=Lab CA/CN=lab-root-ca"

openssl genrsa -out tls.key 2048
openssl req -new \
    -key tls.key \
    -out tls.csr \
    -config csr.conf

openssl x509 -req \
    -in tls.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out tls.crt \
    -days 365 \
    -sha256 \
    -extensions req_ext \
    -extfile csr.conf