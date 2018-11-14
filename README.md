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

### Output format

Example output format:

```
Listeners:
Listener: 10.1.68.184_9080
  Route: 'inbound|9080||reviews.default.svc.cluster.local'
  CA root-cert.pem 9bf28610a7e5e165faec7505442306ba (days until expiration: 349)
  chain cert-chain.pem c6e8ca9416dae28ee0655e1d91cdaea2 (days until expiration: 0)
  Successful HTTP 2xx 22
Listener: 10.1.68.184_9443
  Uses Istio Mixer
  TCP target cluster: 'inbound|9443||reviews.default.svc.cluster.local'
  CA root-cert.pem 9bf28610a7e5e165faec7505442306ba (days until expiration: 349)
  chain cert-chain.pem c6e8ca9416dae28ee0655e1d91cdaea2 (days until expiration: 0)
  SSL handshakes: 0
Listener: 0.0.0.0_9080
  RDS Route: '9080'
  Successful HTTP 2xx 22

Routes:
Route: inbound|9080||reviews.default.svc.cluster.local
  Domain: *
    {"prefix":"/"} => inbound|9080||reviews.default.svc.cluster.local
Route: 9080
  Warning: None of the 4 known virtual hosts has traffic stats

Clusters:
Cluster: xds-grpc
  => istio-pilot.istio-system:15011
  CA root-cert.pem 9bf28610a7e5e165faec7505442306ba (days until expiration: 349)
  chain cert-chain.pem c6e8ca9416dae28ee0655e1d91cdaea2 (days until expiration: 0)
  Successful HTTP 2xx 1978
  ERRORS 503: 18
Cluster: zipkin
  => zipkin.istio-system:9411
Cluster: inbound|9080||reviews.default.svc.cluster.local
  => 127.0.0.1:9080
  WARNING No successful HTTP traffic
Cluster: inbound|9443||reviews.default.svc.cluster.local
  => 127.0.0.1:9443
  WARNING No successful HTTP traffic
```

Future: It would be cool to produce a diagram.  I have some ideas.
Email/Slack snible@us.ibm.com to collaborate.

# Developer

Test offline by downloading pod:15000/config_dump, /stats, and /certs and running `node cli.js <config_dump> <stats> <certs>`.  For example `node ./cli.js testdata/pp-config_dump.json testdata/pp-stats.txt testdata/pp-certs.json`

Before pushing run _testdata/testcases.sh_.  If it concludes with "Tests pass" then the code is probably OK.
