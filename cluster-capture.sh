#!/bin/bash
set -o errexit

export CAPTURE_DIR=$1

if [ -z "$CAPTURE_DIR" ]; then
    echo "Usage: $0 <dirname-for-results>"
    exit 1
fi

scrape_pod () {
  export POD=$1
  echo "Scraping pod $POD in namespace $NAMESPACE"
  # TODO handle two pods with same fullname in same namespace
  set +e
  kubectl --namespace $NAMESPACE exec $POD -c istio-proxy -- curl --silent localhost:15000/config_dump > $CAPTURE_DIR/$POD-config_dump.json
  CAN_SCRAPE=$?
  set -o errexit
  if [ $CAN_SCRAPE -eq 0 ]; then
    kubectl --namespace $NAMESPACE exec $POD -c istio-proxy -- curl --silent localhost:15000/stats > $CAPTURE_DIR/$POD-stats.txt
    kubectl --namespace $NAMESPACE exec $POD -c istio-proxy -- curl --silent localhost:15000/certs > $CAPTURE_DIR/$POD-certs.json
    kubectl --namespace $NAMESPACE exec $POD -c istio-proxy -- curl --silent localhost:15000/clusters > $CAPTURE_DIR/$POD-clusters.txt
  else
    rm $CAPTURE_DIR/$POD-config_dump.json
  fi
}
export -f scrape_pod

scrape_ns () {
  export NAMESPACE=$1
  echo "Scraping namespace $NAMESPACE"
  kubectl --namespace $1 get pods -o=custom-columns=NAME:.metadata.name --no-headers=true \
 	| xargs -n 1 -P 10 -I {} bash -c 'scrape_pod "$@"' _ {}
}

mkdir -p $CAPTURE_DIR

kubectl get pods --all-namespaces -o json > $CAPTURE_DIR/pods.json

# TODO let user choose which namespaces
scrape_ns "istio-system"
scrape_ns "default"
