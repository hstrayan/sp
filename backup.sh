#!/bin/bash

if [ ! -d /backup ]; then
 mkdir /backup
fi
# perform backup
SRCDIR=/rolodex-data
TIME=$(date +"%m-%d-%Y")
FILENAME=rolodex.$TIME.tar.gz
#backup
tar -cvzf /backup/$FILENAME $SRCDIR
#rotate logs every 60 days
if [ -e /backup/*.gz ]; then
 find /backup -mtime +60 -type f -delete
fi
