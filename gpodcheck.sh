#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z "$1" ]; then
    echo "Usage: $0 <context>"
    exit 1
fi

POD=$1

>&2 echo Graphical PodCheck for $POD
node $SCRIPTPATH/genhtml.js \
	<(kubectl exec $POD -c istio-proxy -- curl --silent localhost:15000/config_dump) \
	<(kubectl exec $POD -c istio-proxy -- curl --silent localhost:15000/stats) \
	<(kubectl exec $POD -c istio-proxy -- curl --silent localhost:15000/certs) \
	