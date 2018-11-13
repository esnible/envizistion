#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for prefix in det mk mk2 pp pp11 rev; do
  node $SCRIPTPATH/../cli.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json
done
