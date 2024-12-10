#!/bin/bash

if [ "$1" = "" ] ; then
    echo "Missing base URL"
    exit 1
fi
if [ "$2" = "" ] ; then
    echo "Missing path."
    exit 1
fi
REQ_METHOD=GET
if [ "$3" != "" ] ; then
    REQ_METHOD=$3
fi

if [ "$OTA_KEY" = "" ] ; then
    echo "Missing OTA_KEY variable"
    exit 1
fi

OTA_SIG=`echo -n "${REQ_METHOD}.${2}" | openssl enc -aes-256-ecb -K "$OTA_KEY" -e | base64 -w 0`
echo "Sig:  $OTA_SIG"

curl -X $REQ_METHOD \
  -H "OTA-Sig: $OTA_SIG" \
  -v ${1}{$2}

