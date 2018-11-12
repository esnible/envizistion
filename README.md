# Envizistion

Envoy Visualization of Istio Configuration

Usage `./podcheck.sh <pod>`

*Envizistion* attempts to summarize the Envoy configuration in human readable form.  The
current version merely writes text to standard output.

A future version will generate a picture for the browser.  I will try to get it put into the Istio sidecar because the current output is too hard to search for misconfigurations.

## For pods in the istio-system namespace

Usage `./syspodcheck.sh <pod>`

You should be able to check the Ingress and Egress Gateways.

If the IngressGateway reports `WARNING: No listeners` it means that you
have not defined any Gateways and VirtualServices. 

# Developer

Test offline by downloading pod:15000/config_dump, /stats, and /certs and running `node cli.js <config_dump> <stats> <certs>`.  For example `node ./cli.js testdata/pp-config_dump.json testdata/pp-stats.txt testdata/pp-certs.json`
