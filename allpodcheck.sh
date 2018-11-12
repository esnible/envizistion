#!/bin/bash
set -o errexit

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

kubectl get pods -o=custom-columns=NAME:.metadata.name --no-headers=true \
	| xargs -n 1 $SCRIPTPATH/podcheck.sh
