# Envizistion

Envoy Visualization of Istio Configuration

Usage `./podcheck.sh <pod>`

The current version writes a few facts to standard out.

A future version will generate a picture for the browser.  I will try to get it put into the Istio sidecar because the current output is too hard to search for misconfigurations.

# Developer

Test offline by downloading pod:15000/config_dump, /stats, and /certs and running `node cli.js <config_dump> <stats> <certs>`.  For example `node ./cli.js testdata/pp-config_dump.json testdata/pp-stats.txt testdata/pp-certs.json`
