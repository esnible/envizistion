// Licensed Materials - Property of IBM
// (C) Copyright IBM Corp. 2018. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or
// disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
// Copyright 2018 IBM Corporation


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
	    var escapes = escapesFromConfig(configDump);
	    
		fs.readFile(statsName, 'utf8', function (err, statsData) {
		    if (err) throw err;

			fs.readFile(certsName, 'utf8', function (err, certsData) {
			    if (err) throw err;
			    var certs = JSON.parse(certsData);
			    processEnvoy(configDump, processStatsData(statsData, escapes), processCertJson(certs))
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
	if (listeners.dynamic_active_listeners) {
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
				retval.push(staticRoute.route_config.name);
			}
		}
		for (var dynamicRoute of routes.dynamic_route_configs) {
			retval.push(dynamicRoute.route_config.name);
		}
	}
	return retval;
}

function escapesFromClusters(clusters) {
	var retval = [];
	for (var staticCluster of clusters.static_clusters) {
		retval.push(staticCluster.cluster.name);
	}
	for (var dynamicCluster of clusters.dynamic_active_clusters) {
		retval.push(dynamicCluster.cluster.name);
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
function processCertJson(rawCerts) {
	var retval = {}
	for (var prop in rawCerts) {
		var val = rawCerts[prop]
		var matches = val.match(
				/^Certificate Path: ([^,]*), Serial Number: ([^,]*), Days until Expiration: (.*)/);
		retval[matches[1]] = {serial: matches[2], daysLeft: matches[3]};
	}
	return retval;
}

function clusterHasTraffic(cluster, stats) {
	var clusterStats = stats.cluster[cluster];
	if (!clusterStats) {
		console.log("warning no stats for cluster " + cluster);
		return false; // should never happen, might happen if there is a stats/config mismatch
	}
	return clusterStats.upstream_rq_2xx > 0
		|| clusterStats.upstream_rq_4xx > 0
		|| clusterStats.upstream_rq_5xx > 0;
		// TODO || with local.ssl.connection_error or other errors if possible/needed 
}

function listenerHasTraffic(listener, stats) {
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

function printListener(listener, stats, certs, outRoutes) {
	// console.log(JSON.stringify(listener));
	console.log("Listener: " + listener.name);
	
	for (var filterChain of listener.filter_chains) {
			
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				if (filter.config.route_config) {
					// console.log("  HTTP Connection Mgr filterChain[i].filters[j].config.route_config has keys " + Object.keys(filter.config.route_config));
					console.log("  Route: '" + filter.config.route_config.name + "'");
					outRoutes.push(filter.config.route_config.name);
					// Ignore the other fields; they will be shown with Routes
				}
				if (filter.config.rds) {
					// console.log("  HTTP Connection Mgr filterChain[i].filters[j].config.rds has keys " + Object.keys(filter.config.rds));
					console.log("  RDS Route: '" + filter.config.rds.route_config_name + "'");
					outRoutes.push(filter.config.rds.route_config_name);
				}
			} else {
				console.log("  Filter name: " + filter.name + " has keys " + Object.keys(filter));
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

	if (stats.listener[listener.name].http[listener.name].downstream_rq_2xx > 0) {
		console.log("  Successful HTTP 2xx " + stats.listener[listener.name].http[listener.name].downstream_rq_2xx);
	}
	if (stats.listener[listener.name].http[listener.name].downstream_rq_4xx > 0) {
		console.log("  4xx ERRORS " + stats.listener[listener.name].http[listener.name].downstream_rq_4xx);
	}
	if (stats.listener[listener.name].http[listener.name].downstream_rq_5xx > 0) {
		console.log("  5xx ERRORS " + stats.listener[listener.name].http[listener.name].downstream_rq_5xx);
	}
}

function printRoute(routeConfig, stats, outClusters) {
	console.log("Route: " + routeConfig.name);
	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		for (var route of virtualHost.routes) {
			if (clusterHasTraffic(route.route.cluster, stats) || route.route.cluster.startsWith("inbound|")) {
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
				outClusters.push(route.route.cluster);
			}
		}
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

	if (stats.cluster[cluster.name].upstream_rq_2xx > 0) {
		console.log("  Successful HTTP 2xx " + stats.cluster[cluster.name].upstream_rq_2xx);
	} else if (cluster.name.startsWith('inbound|')) {
		console.log("  WARNING No successful HTTP traffic");
	}
	if (stats.cluster[cluster.name].upstream_rq_4xx > 0) {
		console.log("  4xx ERRORS " + stats.cluster[cluster.name].upstream_rq_4xx);
	}
	if (stats.cluster[cluster.name].upstream_rq_5xx > 0) {
		console.log("  5xx ERRORS " + stats.cluster[cluster.name].upstream_rq_5xx);
	}
}

function processEnvoy(configDump, stats, certs) {
	console.log("Listeners with traffic:");
	var listenersWithTraffic = 0;
	var referencedRoutes = [];
	if (configDump.configs.listeners.dynamic_active_listeners) {
		for (var activeListener of configDump.configs.listeners.dynamic_active_listeners) {
			if (listenerHasTraffic(activeListener.listener.name, stats)) {
				printListener(activeListener.listener, stats, certs, referencedRoutes);
				listenersWithTraffic++;
			}
		}
	}
	console.log();

	console.log("Referenced Routes:");
	var referencedClusters = [];
	if (configDump.configs.routes) {
		if (configDump.configs.routes.static_route_configs) {
			for (var staticRoute of configDump.configs.routes.static_route_configs) {
				printRoute(staticRoute.route_config, stats, referencedClusters);
			}
		} else {
			console.log("WARNING: No static_route_configs");
		}
		for (var dynamicRoute of configDump.configs.routes.dynamic_route_configs) {
			if (referencedRoutes.indexOf(dynamicRoute.route_config.name) >= 0) { 
				printRoute(dynamicRoute.route_config, stats, referencedClusters);
			}
		}
	}
	console.log();

	console.log("Clusters with traffic:");
	for (var staticCluster of configDump.configs.clusters.static_clusters) {
		printCluster(staticCluster.cluster, stats, certs);
	}
	for (var dynamicCluster of configDump.configs.clusters.dynamic_active_clusters) {
		if (clusterHasTraffic(dynamicCluster.cluster.name, stats)
				|| referencedClusters.indexOf(dynamicCluster.cluster.name) >= 0) {
			printCluster(dynamicCluster.cluster, stats, certs);
		}
	}
}

try {
	main();
} catch (err) {
	process.exit(1);
}
