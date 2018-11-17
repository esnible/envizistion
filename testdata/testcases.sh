#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for prefix in det mk mk2 pp pp11 myc rev sig s; do
  node $SCRIPTPATH/../cli.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json
  node $SCRIPTPATH/../genhtml.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json
done

echo
echo Tests pass!
