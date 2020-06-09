// Licensed Materials - Property of IBM
// (C) Copyright IBM Corp. 2018. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"use strict";

var fs = require('fs');

function main() {
	if (process.argv.length < 5) {
		console.log("Usage: node cli.js config_dump.json stats.txt certs.txt")
		return 1
	}
	var configDumpName = process.argv[2];
	var statsName = process.argv[3];
	var certsName = process.argv[4];

	fs.readFile(configDumpName, 'utf8', function (err, configDumpData) {
	    if (err) throw err;
	    var configDump = JSON.parse(configDumpData);

		fs.readFile(statsName, 'utf8', function (err, statsData) {
		    if (err) throw err;

			fs.readFile(certsName, 'utf8', function (err, certsData) {
			    if (err) throw err;
			    var certs = JSON.parse(certsData);
			    processEnvoy11(configDump, statsData, processCertsJson11(certs))
			});
		});
	});

	return 0
}

// Given an Envoy configuration, generate a map of name=>name.replace('.', '~')
// for every named thing that includes dots that we expect to see in stats
function escapesFromConfig(config) {
	var entities = escapesFromListeners(config.configs.listeners)
		.concat(escapesFromRoutes(config.configs.routes))
		.concat(escapesFromClusters(config.configs.clusters));
	var retval = {};
	for (var entity of entities) {
		if (entity.indexOf(".") > 0) {
			retval[entity] = entity.replace(/\./g, '~');	// all . to ~
		}
	}
	return retval;
}

// Extract listener names from Envoy config
function escapesFromListeners(listeners) {
	var retval = [];
	if (listeners && listeners.dynamic_active_listeners) {
		for (var activeListener of listeners.dynamic_active_listeners) {
			retval.push(activeListener.listener.name);
		}
	}
	return retval;
}

function escapesFromRoutes(routes) {
	var retval = [];
	if (routes) {
		if (routes.static_route_configs) {
			for (var staticRoute of routes.static_route_configs) {
				if (staticRoute.route_config.name) {
					retval.push(staticRoute.route_config.name);
				}
				// If there is no name there might be a virtual_hosts[]
				// but we ignore those routes.
			}
		}
		if (routes.dynamic_route_configs) {
			for (var dynamicRoute of routes.dynamic_route_configs) {
				retval.push(dynamicRoute.route_config.name);
			}
		}
	}
	return retval;
}

function escapesFromClusters(clusters) {
	var retval = [];
	if (clusters) {
		for (var staticCluster of clusters.static_clusters) {
			retval.push(staticCluster.cluster.name);
		}
		if (clusters.dynamic_active_clusters) {
			for (var dynamicCluster of clusters.dynamic_active_clusters) {
				retval.push(dynamicCluster.cluster.name);
			}
		}
	}
	return retval;
}

// s is a string like "cluster.inbound|9080||details.default.svc.cluster.local.external.upstream_rq_2xx"
// and we will convert it into a string like "cluster.inbound|9080||details~default~svc~cluster~local.external.upstream_rq_2xx"
// if escapes, a map, is something like { "inbound|9080||details.default.svc.cluster.local" => "inbound|9080||details~default~svc~cluster~local" }
function escapeLine(s, escapes) {
	for (var escape of Object.keys(escapes)) {
		do {
			var prevS = s;
			s = s.replace(escape, escapes[escape]);
		} while (prevS != s);
	}
	return s;
}

// statsData is a string of lines, each line has a format like
// "cluster.inbound|9080||details.default.svc.cluster.local.external.upstream_rq_2xx: 6"
// but because the periods that are part of cluster and listener names aren't escaped we
// can process this by splitting on "."
function processStatsData(statsData, escapes) {
	var retval = {}
	var lines = statsData.split("\n");
	var reversedEscapes = Object.keys(escapes)
    	.reduce(function(accum, key) { accum[escapes[key]] = key; return accum; }, {});
	lines.forEach(function(line) {
		line = escapeLine(line, escapes);
		var keyVal = line.split(": ");
		var traversal = keyVal[0].split('.');
		var subval = retval, prevSubval, prevKey;
		traversal.forEach(function(key) {
			var rkey = reversedEscapes[key];
			if (rkey) {
				key = rkey;
			}
			var newSubval = subval[key];
			if (!newSubval) {
				newSubval = {};
				subval[key] = newSubval;
			}
			prevSubval = subval;
			subval = newSubval;
			prevKey = key;
		});
		var val = keyVal[1];
		try {
			val = parseInt(keyVal[1]);
		} catch (err) {
			// do nothing; keep string
		}
		prevSubval[prevKey] = val;
	});
	return retval;
}

// rawCerts is a map with keys "ca_cert" and "cert_chain" and values
// like "Certificate Path: /etc/certs/root-cert.pem, Serial Number: 9bf28610a7e5e165faec7505442306ba, Days until Expiration: 355"
// *or* a map with keys "certificates"
function processCertJson(rawCerts) {
	// Parse the old-style /certs output
	var retval = {}
	for (var prop in rawCerts) {
		var val = rawCerts[prop]
		var matches = val.match(
				/^Certificate Path: ([^,]*), Serial Number: ([^,]*), Days until Expiration: (.*)/);
		retval[matches[1]] = {serial: matches[2], daysLeft: matches[3]};
	}
	return retval;
}

// rawCerts is a map with key certificates, an array containing
// map with keys ca_cert and cert_chain
// Istio 1.1
function processCertsJson11(rawCerts) {
	if (!rawCerts.certificates) {
		return processCertJson(rawCerts);
	}
	var retval = {}
	for (var certificate of rawCerts.certificates) {
		for (var cert of certificate.ca_cert) {
			retval[cert.path] = {serial: cert.serial_number, daysLeft: cert.days_until_expiration};
		}
		for (var cert of certificate.cert_chain) {
			retval[cert.path] = {serial: cert.serial_number, daysLeft: cert.days_until_expiration};
		}
	}
	return retval;
}

function clusterHasTraffic(cluster, stats) {
	var clusterStats = stats.cluster[cluster];
	if (!clusterStats) {
		console.log("warning no stats for cluster " + cluster); // happens if no K8s Service references pod
		return false; // should never happen, might happen if there is a stats/config mismatch
	}
	return clusterStats.upstream_rq_2xx > 0
		|| clusterStats.upstream_rq_4xx > 0
		|| clusterStats.upstream_rq_5xx > 0
		|| clusterStats.upstream_cx_connect_fail > 0;
}

function listenerHasTraffic(listener, stats) {
	if (process.env.SHOWALL) {
		return true;
	}
	if (!stats.listener || !(listener in stats.listener)) { // e.g. "virtual"
		return false;
	}
	return stats.listener[listener].downstream_cx_total > 0;
}

function printCert(label, filename, certs) {
	if (!(filename in certs)) {
		console.log("  Warning unknown cert " + filename + ", names are " + Object.keys(certs));
		return;
	}
	console.log("  " + label + " " + filename.split('/').slice(-1)[0] + " " +
	  certs[filename].serial + " (days until expiration: " + certs[filename].daysLeft + ")");
}

function printListener(listener, stats, certs, outRoutes, outClusters) {
	// console.log(JSON.stringify(listener));
	console.log("Listener: " + listener.name);

	if (listener.listener_filters) {
		// This is typically the envoy.listener.tls_inspector
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/listener_filters/tls_inspector#config-listener-filters-tls-inspector
		console.log("  Filters: " + listener.listener_filters.map(function(lf) { return lf.name; }).join(", "));
	}

	var trafficExpected = true;
	for (var filterChain of listener.filter_chains) {

		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				var config = (filter.typed_config) ? filter.typed_config : filter.config;
				if (config.route_config) {
					// console.log("  HTTP Connection Mgr filterChain[i].filters[j].config.route_config has keys " + Object.keys(filter.config.route_config));
					console.log("  Route: '" + config.route_config.name + "'");
					outRoutes.push(config.route_config.name);
					// Ignore the other fields; they will be shown with Routes
				}
				if (config.rds) {
					// console.log("  HTTP Connection Mgr filterChain[i].filters[j].config.rds has keys " + Object.keys(filter.config.rds));
					console.log("  RDS Route: '" + config.rds.route_config_name + "'");
					outRoutes.push(config.rds.route_config_name);
				}
			} else if (filter.name == "mixer") {
				// Ignore filter.config for mixer filters
				console.log("  Uses Istio Mixer");
			} else if (filter.name == "envoy.tcp_proxy") {
				console.log("  TCP target cluster: '" + filter.config.cluster + "'");
				outClusters.push(filter.config.cluster);
			} else if (filter.name == "envoy.filters.network.sni_cluster") {
				console.log("  Multicluster: Uses SNI name as cluster name");
				trafficExpected = false;
			} else if (filter.name == "envoy.filters.network.tcp_cluster_rewrite") {
				console.log("  Multicluster: Rewrites '" + filter.config.cluster_pattern + "' to '" + filter.config.cluster_replacement + "'");
			} else {
				console.log("  UNSUPPORT DUMP for filter type name: " + filter.name + " which has keys " + Object.keys(filter));
			}
		}

		if (filterChain.tls_context) {
			printCert("CA", filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs);
			// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
			for (var tlsCertificate of filterChain.tls_context.common_tls_context.tls_certificates) {
				printCert("chain", tlsCertificate.certificate_chain.filename, certs);
				// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
				// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
			}
		}
	}

	// TODO Replace this ad-hoc logic with parsing of `stat_prefix` in config dump.
	var listenerHttp;
	if (stats.http && stats.http[listener.name]) {
		listenerHttp = stats.http[listener.name];
	} else if (stats.listener && stats.listener[listener.name] &&
			stats.listener[listener.name].http &&
			stats.listener[listener.name].http[listener.name]) {
		listenerHttp = stats.listener[listener.name].http;
	}

	if (listenerHttp) {
		if (listenerHttp.downstream_rq_2xx > 0) {
			console.log("  Successful HTTP 2xx " + listenerHttp.downstream_rq_2xx);
		} else {
			console.log("  Warning no successful HTTP");
		}
		if (listenerHttp.downstream_rq_4xx > 0
				|| listenerHttp.downstream_rq_5xx > 0) {
			console.log("  ERRORS " + renderBreakdown(listenerHttp, /downstream_rq_([45]..)/));
		}
	}

	if (stats.listener && stats.listener[listener.name] && stats.listener[listener.name].ssl) {
		console.log("  SSL handshakes: " + stats.listener[listener.name].ssl.handshake);
		if (stats.listener[listener.name].ssl.connection_error) {
			console.log("  SSL connection errors: " + stats.listener[listener.name].ssl.connection_error);
		}
	} else if (!listenerHttp && trafficExpected) {
		console.log("  WARNING: No SSL or HTTP traffic stats");
	}
}

// renderBreakdown returns a human-readable string for the properties of h that match regex
function renderBreakdown(h, regex) {
	var retval = [];
	for (var keyval of Object.entries(h)) {
		var match = keyval[0].match(regex);
		if (match && match[1]) {
			retval.push([match[1], keyval[1]]);
		}
	}
	return retval.map(function(keyval) { return keyval[0] + ": " + keyval[1]; }).join(", ");
}

function printRoute(routeConfig, stats, outClusters) {
	if (!routeConfig.name) {
		return; // Ignore "virtualHost" style route
	}
	console.log("Route: " + routeConfig.name);
	var clustersDisplayed = 0;
	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		for (var route of virtualHost.routes) {
			if (clusterHasTraffic(route.route.cluster, stats) || route.route.cluster.startsWith("inbound|")) {
				clustersDisplayed++;

				if (!printedDomains) {
					if (virtualHost.domains.length == 1) {
						console.log("  Domain: " + virtualHost.domains[0]);
					} else {
						var domain = virtualHost.domains.concat().sort(function(a, b) { return a.length - b.length; }).slice(-1)[0];
						console.log("  Domains: " + domain + " etc.");
					}

					printedDomains = true;
				}
				console.log("    " + JSON.stringify(route.match) + " => " + route.route.cluster);
				if (route.route.host_rewrite) {
					console.log("      (rewritten " + route.route.host_rewrite + ")");
				}
				outClusters.push(route.route.cluster);
			} else {
				// console.log("    Skipping " + route.route.cluster);
			}
		}
	}

	if (clustersDisplayed == 0) {
		console.log("  Warning: None of the " + routeConfig.virtual_hosts.length + " known virtual hosts has traffic stats");
	}
}

function printCluster(cluster, stats, certs) {
	console.log("Cluster: " + cluster.name);
	if (cluster.hosts) {
		for (var host of cluster.hosts) {
			if (host.socket_address) {
				console.log("  => " + host.socket_address.address + ":" + host.socket_address.port_value);
		    }
		}
	}

	if (cluster.tls_context) {
		printCert("CA", cluster.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs);
		// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
		// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
		for (var tlsCertificate of cluster.tls_context.common_tls_context.tls_certificates) {
			printCert("chain", tlsCertificate.certificate_chain.filename, certs);
			// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
		}
	}

	if (stats.cluster[cluster.name]) {
		if (stats.cluster[cluster.name].upstream_rq_2xx > 0) {
			console.log("  Successful HTTP 2xx " + stats.cluster[cluster.name].upstream_rq_2xx);
		} else if (cluster.name.startsWith('inbound|')) {
			console.log("  WARNING No successful HTTP traffic");
		}
		if (stats.cluster[cluster.name].upstream_rq_4xx > 0
				|| stats.cluster[cluster.name].upstream_rq_5xx > 0) {
			console.log("  ERRORS " + renderBreakdown(stats.cluster[cluster.name], /upstream_rq_([45][0-9][0-9])/));
		}
		if (stats.cluster[cluster.name].upstream_cx_connect_fail > 0) {
			console.log("  CONNECTION FAILURES " + stats.cluster[cluster.name].upstream_cx_connect_fail);
		}
	}
}

function inboundListener(listener) {
	for (var filterChain of listener.filter_chains) {
		// If the listener is terminating TLS consider it inbound
		if (filterChain.tls_context) {
			return true;
		}
	}
	return false;
}

function processEnvoy11(configDump, rawStats, certs) {
	if (configDump.configs.bootstrap) {
	    var escapes = escapesFromConfig(configDump);
		return processEnvoy(configDump, processStatsData(rawStats, escapes), certs);
	}

	console.log("(Envoy new style)");

	// each config has a "@type":
	// - type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump
	// - type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump
	// - type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump
	// - type.googleapis.com/envoy.admin.v2alpha.RoutesConfigDump
	var typedConfig = {}
	var lookup = {
			["type.googleapis.com/envoy.admin.v2alpha.BootstrapConfigDump"]: "bootstrap",
			["type.googleapis.com/envoy.admin.v2alpha.ClustersConfigDump"]: "clusters",
			["type.googleapis.com/envoy.admin.v2alpha.ListenersConfigDump"]: "listeners",
			["type.googleapis.com/envoy.admin.v2alpha.RoutesConfigDump"]: "routes",
			["type.googleapis.com/envoy.admin.v3.BootstrapConfigDump"]: "bootstrap",
			["type.googleapis.com/envoy.admin.v3.ClustersConfigDump"]: "clusters",
			["type.googleapis.com/envoy.admin.v3.ListenersConfigDump"]: "listeners",
			["type.googleapis.com/envoy.admin.v3.RoutesConfigDump"]: "routes",
			["type.googleapis.com/envoy.admin.v3.ScopedRoutesConfigDump"]: "scopedroutes",	// TODO
			["type.googleapis.com/envoy.admin.v3.SecretsConfigDump"]: "secrets", // TODO
	}
	for (var config of configDump.configs) {
		if (config["@type"] in lookup) {
			typedConfig[lookup[config["@type"]]] = config;
		} else {
			console.log("Unexpected @type " + config["@type"]);
		}
	}
	// For now, make the config look old-style
	var configDump10 = {configs: typedConfig};
    var escapes = escapesFromConfig(configDump10);

	processEnvoy(configDump10, processStatsData(rawStats, escapes), certs);
}

function printBootstrap(bootstrap) {
	if (bootstrap.bootstrap.node.metadata) {
		console.log("Istio version: " + bootstrap.bootstrap.node.metadata.ISTIO_VERSION);
	}
	console.log("Envoy version: " + bootstrap.bootstrap.node.build_version);
	console.log();
}

function allListeners(configDump) {
	var retval = [];
	if (configDump.configs.listeners) {
		if (configDump.configs.listeners.dynamic_active_listeners) {
			retval = retval.concat(configDump.configs.listeners.dynamic_active_listeners
					.map(function(l) { return l.listener; }));
		}
		if (configDump.configs.listeners.dynamic_listeners) {
			retval = retval.concat(configDump.configs.listeners.dynamic_listeners
					.map(function(l) {
						return l.active_state.listener;
						}));
		}
		if (configDump.configs.listeners.static_listeners) {
			retval = retval.concat(configDump.configs.listeners.static_listeners
					.map(function(l) { return l.listener; }));
		}
	}

	return retval;
}

function processEnvoy(configDump, stats, certs) {
	printBootstrap(configDump.configs.bootstrap);

	console.log("Listeners:");
	var listenersWithTraffic = 0;
	var inboundListeners = 0;
	var referencedRoutes = [];
	var referencedClusters = [];
	for (var listener of allListeners(configDump)) {
		var printed = false;
		if (listenerHasTraffic(listener.name, stats)) {
			printListener(listener, stats, certs, referencedRoutes, referencedClusters);
			printed = true;
			listenersWithTraffic++;
		}
		if (inboundListener(listener)) {
			if (!printed) {
				printListener(listener, stats, certs, referencedRoutes, referencedClusters);
			}
			inboundListeners++;
		}
	}
	if (inboundListeners == 0) {
		console.log("WARNING: No inbound listener (no K8s Service matches the pod; or no Istio control plane connectivity)");
	} else if (listenersWithTraffic == 0) {
		console.log("WARNING: No traffic");
	}
	console.log();

	console.log("Routes:");
	if (configDump.configs.routes) {
		if (configDump.configs.routes.static_route_configs) {
			for (var staticRoute of configDump.configs.routes.static_route_configs) {
				// Note that there really are duplicates; and this duplicates print
				printRoute(staticRoute.route_config, stats, referencedClusters);
			}
		} else {
			console.log("WARNING: No static_route_configs");
		}
		if (configDump.configs.routes.dynamic_route_configs) {
			for (var dynamicRoute of configDump.configs.routes.dynamic_route_configs) {
				if (referencedRoutes.indexOf(dynamicRoute.route_config.name) >= 0) {
					printRoute(dynamicRoute.route_config, stats, referencedClusters);
				}
			}
		}
	}
	console.log();

	console.log("Clusters:");
	if (configDump.configs.clusters) {
		for (var staticCluster of configDump.configs.clusters.static_clusters) {
			printCluster(staticCluster.cluster, stats, certs);
		}
		if (configDump.configs.clusters.dynamic_active_clusters) {
			for (var dynamicCluster of configDump.configs.clusters.dynamic_active_clusters) {
				if (clusterHasTraffic(dynamicCluster.cluster.name, stats)
						|| referencedClusters.indexOf(dynamicCluster.cluster.name) >= 0) {
					printCluster(dynamicCluster.cluster, stats, certs);
				}
			}
		}
	}
}

try {
	main();
} catch (err) {
	process.exit(1);
}
