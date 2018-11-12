#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z "$1" ]; then
    echo "Usage: $0 <context>"
    exit 1
fi

POD=$1

echo PodCheck for $POD in istio-system namespace
node $SCRIPTPATH/cli.js \
	<(kubectl -n istio-system exec $POD -c istio-proxy -- curl --silent localhost:15000/config_dump) \
	<(kubectl -n istio-system exec $POD -c istio-proxy -- curl --silent localhost:15000/stats) \
	<(kubectl -n istio-system exec $POD -c istio-proxy -- curl --silent localhost:15000/certs) \
	