#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

KARGS=""
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

if [[ ! -z $NAMESPACE ]]; then
  ARGS="$ARGS --namespace $NAMESPACE"
  KARGS="$KARGS --namespace $NAMESPACE"
fi

if [[ ! -z $CONTEXT ]]; then
  ARGS="$ARGS --context $CONTEXT"
  KARGS="$KARGS --context $NAMESPACE"
fi

echo "<!DOCTYPE html>"
echo "<html>"
echo "<head>"
echo "<title>Envistion</title>"
echo "<link rel='stylesheet' href='genhtml.css'>"
echo "</head>"
echo "<body>"

kubectl $ARGS get pods -o=custom-columns=NAME:.metadata.name --no-headers=true \
	| xargs -n 1 $SCRIPTPATH/gpodcheck.sh $ARGS

echo "</body>"
echo "</html>"
