#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ARGS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NAMESPACE=$2
      shift
      ;;
    -n)
      NAMESPACE=$2
      shift
      ;;
    --context)
      CONTEXT=$2
      shift
      ;;
    *)
      POD=$1
  esac

  shift
done

if [ -z "$POD" ]; then
    echo "Usage: $0 [--namespace <namespace>] <pod>"
    exit 1
fi


if [[ ! -z $CONTEXT ]]; then
  ARGS="$ARGS --context $CONTEXT"
fi

if [[ ! -z $NAMESPACE ]]; then
  ARGS="$ARGS --namespace $NAMESPACE"
fi

>&2 echo Graphical PodCheck for $POD
node $SCRIPTPATH/genhtml.js \
	<(kubectl $ARGS exec $POD -c istio-proxy -- curl --silent localhost:15000/config_dump) \
	<(kubectl $ARGS exec $POD -c istio-proxy -- curl --silent localhost:15000/stats) \
	<(kubectl $ARGS exec $POD -c istio-proxy -- curl --silent localhost:15000/certs) \
	<(kubectl $ARGS exec $POD -c istio-proxy -- curl --silent localhost:15000/clusters)
