#!/bin/bash

if [ "$1" = "" ] ; then
    echo "Missing base URL"
    exit 1
fi
if [ "$2" = "" ] ; then
    echo "Missing tgz filename."
    exit 1
fi

FILE_HASH=`sha256sum $2 | awk '{ print $1 }'`
FILE_LEN=`ls -l $2 | awk '{ print $5 }'`
echo "Len:  $FILE_LEN"
echo "Hash: $FILE_HASH"

if [ "$OTA_KEY" = "" ] ; then
    echo "Missing OTA_KEY variable"
    exit 1
fi

OTA_SIG=`echo -n ${FILE_HASH}.${FILE_LEN} | openssl enc -aes-256-ecb -K "$OTA_KEY" -e | base64 -w 0`
echo "Sig:  $OTA_SIG"

curl -X POST --data-binary @$2 \
  -H "OTA-Sig: $OTA_SIG" \
  -H "OTA-Hash: $FILE_HASH" \
  -v $1/ota/update

