#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for prefix in det mk mk2 pp pp11 myc rev sig s delay headers pilot egress istio-egressgateway-76d84fb6bf-nwrz4 ppp web auth ing5000 ing5000b pprbac; do
  node $SCRIPTPATH/../cli.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json
  if [ -f /tmp/foo.txt ]; then # Work-around because we didn't save /clusters for all test cases
    node $SCRIPTPATH/../vizfile.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json $SCRIPTPATH/${prefix}-clusters.json
  else
    node $SCRIPTPATH/../vizfile.js $SCRIPTPATH/${prefix}-config_dump.json $SCRIPTPATH/${prefix}-stats.txt $SCRIPTPATH/${prefix}-certs.json
  fi
done

echo
echo Tests pass!
