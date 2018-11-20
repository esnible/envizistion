// Licensed Materials - Property of IBM
// (C) Copyright IBM Corp. 2018. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or
// disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
// Copyright 2018 IBM Corporation


"use strict";

var fs = require('fs');

function main() {
	if (process.argv.length < 5) {
		console.log("Usage: node genhtml.js config_dump.json stats.txt certs.txt")
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
		for (var dynamicCluster of clusters.dynamic_active_clusters) {
			retval.push(dynamicCluster.cluster.name);
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
		console.log("<span class='warning'>warning no stats for cluster " + cluster + "</span>"); // happens if no K8s Service references pod
		return false; // should never happen, might happen if there is a stats/config mismatch
	}
	return clusterStats.upstream_rq_2xx > 0
		|| clusterStats.upstream_rq_4xx > 0
		|| clusterStats.upstream_rq_5xx > 0
		|| clusterStats.upstream_cx_connect_fail > 0;
}

function listenerHasTraffic(listener, stats) {
	if (!stats.listener || !(listener in stats.listener)) { // e.g. "virtual"
		return false;
	}
	return stats.listener[listener].downstream_cx_total > 0;
}

function htmlCert(label, filename, certs, importantDays) {
	if (!(filename in certs)) {
		console.log("  <span class='problem'><b>Warning unknown cert " + filename + ", names are " + Object.keys(certs) + "</b></span><br>");
		return;
	}
	console.log("  " + label + " <i>" + filename.split('/').slice(-1)[0] + "</i> " +
			  certs[filename].serial + "</i><br>");
	if (certs[filename].daysLeft < 0) {
		console.log("  <span class='problem'><b>EXPIRED</b></span><br>");
	} else if (certs[filename].daysLeft < importantDays) {
		console.log("  <span class='warning'>(days until expiration: " + certs[filename].daysLeft + ")</span><br>");
	}
}

function htmlListener(listener, stats, certs) {
	console.log("<div class='listener'>");
	// console.log(JSON.stringify(listener));
	console.log("<b>" + listener.name + "</b><br>");

	if (listener.listener_filters) {
		// This is typically the envoy.listener.tls_inspector
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/listener_filters/tls_inspector#config-listener-filters-tls-inspector
		console.log("-  Filters: " + listener.listener_filters.map(function(lf) { return lf.name; }).join(", ") + "<br>");
	}

	var trafficExpected = true;
	for (var filterChain of listener.filter_chains) {

		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				// Do nothing, we will show these in another column
			} else if (filter.name == "mixer") {
				// Ignore filter.config for mixer filters
				console.log("-  Uses Istio Mixer<br>");
			} else if (filter.name == "envoy.tcp_proxy") {
				console.log("-  TCP cluster => " + filter.config.cluster + "<br>");
			} else if (filter.name == "envoy.filters.network.sni_cluster") {
				console.log("-  Multicluster: Uses SNI name as cluster name<br>");
				trafficExpected = false;
			} else if (filter.name == "envoy.filters.network.tcp_cluster_rewrite") {
				console.log("-  Multicluster: Rewrites '" + filter.config.cluster_pattern + "' to '" + filter.config.cluster_replacement + "'<br>");
			} else {
				console.log("-  UNSUPPORT DUMP for filter type name: " + filter.name + " which has keys " + Object.keys(filter) + "<br>");
			}
		}

		if (filterChain.tls_context) {
			htmlCert("CA", filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs, 10);
			// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
			for (var tlsCertificate of filterChain.tls_context.common_tls_context.tls_certificates) {
				htmlCert("chain", tlsCertificate.certificate_chain.filename, certs, 0);
				// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
				// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
			}
		}
	}

	if (stats.listener[listener.name].http) {
		if (stats.listener[listener.name].http[listener.name].downstream_rq_2xx > 0) {
			console.log("  Successful HTTP 2xx " + stats.listener[listener.name].http[listener.name].downstream_rq_2xx + "<br>");
		} else {
			console.log("  <span class='warning'>Warning no successful HTTP</span><br>");
		}
		if (stats.listener[listener.name].http[listener.name].downstream_rq_4xx > 0
				|| stats.listener[listener.name].http[listener.name].downstream_rq_5xx > 0) {
			console.log("<span class='problem'>ERRORS " + renderBreakdown(stats.listener[listener.name].http[listener.name], /downstream_rq_([45]..)/) + "</span><br>");
		}
	} else if (stats.listener[listener.name].ssl) {
		console.log("  SSL handshakes: " + stats.listener[listener.name].ssl.handshake + "<br>");
		if (stats.listener[listener.name].ssl.connection_error) {
			console.log("<span class='problem'>SSL connection errors: " + stats.listener[listener.name].ssl.connection_error + "</span><br>");
		}
	} else {
		if (trafficExpected) {
			console.log("  <span class='warning'>WARNING: No SSL or HTTP traffic stats</span><br>");
		}
	}
	console.log("</div>");
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

// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-headermatcher
function htmlMatchHeader(header) {
	if (header.exact_match) {
		return header["name"] + "==" + header.exact_match;
	}

	return JSON.stringify(header);
}

function htmlMatchKey(key, val) {
	if (key == "prefix" || key == "path" || key == "regex") {
		return key + " " + val;
	} else if (key == "headers") {
		return "headers " + val.map(function (header) { return htmlMatchHeader(header); }).join("; ");
	}

	return key + " " + JSON.stringify(val);
}

// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-routematch
function htmlMatch(match) {
	return Object.keys(match).map(function(key) { return htmlMatchKey(key, match[key]); }).join(" && ");
}

function htmlPercent(envoyPct) {
	// Don't show 100%
	if (!envoyPct || envoyPct.numerator == 1000000) {
		return "";
	}

	return " (" + Math.round(envoyPct.numerator/10000) + "%)";
}

function htmlEnvoyFault(envoyFault) {
	for (var faultType of Object.keys(envoyFault)) {
		if (faultType == "delay") {
			console.log("DELAY " + envoyFault.delay.fixed_delay + htmlPercent(envoyFault.delay.percentage) + "<br>");
		} else {
			console.log("FAULT INJECTION " + faultType + "<br>");
		}
	}
}

function htmlPerFilterConfig(perFilterConfig) {
	for (var configType of Object.keys(perFilterConfig)) {
		if (configType == "envoy.fault") {
			htmlEnvoyFault(perFilterConfig[configType]);
		} else if (configType == "mixer") {
			// htmlMixerFilterConfig(perFilterConfig[configType]);
		} else {
			console.log(configType + "<br>")
		}
	}
}

function htmlRoute(routeConfig, stats) {
	if (!routeConfig.name) {
		return; // Ignore "virtualHost" style route
	}
	console.log("<div class='route'>");
	console.log("<b>" + routeConfig.name + "</b><br>");
	var clustersDisplayed = 0;
	// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-virtualhost
	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-route
		for (var route of virtualHost.routes) {
			if (clusterHasTraffic(route.route.cluster, stats) || route.route.cluster.startsWith("inbound|")) {
				clustersDisplayed++;

				if (!printedDomains) {
					if (virtualHost.domains.length == 1) {
						console.log(virtualHost.domains[0] + "<br>");
					} else {
						var domain = virtualHost.domains.concat().sort(function(a, b) { return a.length - b.length; }).slice(-1)[0];
						console.log(domain + " etc.<br>");
					}

					printedDomains = true;
				}
				console.log("<div class='route-route'>");
				console.log("    " + htmlMatch(route.match) + " => " + route.route.cluster + "<br>");
				if (route.route.host_rewrite) {
					console.log("      (rewritten " + route.route.host_rewrite + ")<br>");
				}
				if (route.per_filter_config) {
					htmlPerFilterConfig(route.per_filter_config);
				}
				console.log("</div>");
			} else {
				// console.log("    Skipping " + route.route.cluster);
			}
		}
	}

	if (clustersDisplayed == 0) {
		console.log("  <span class='warning'>Warning: None of the " + routeConfig.virtual_hosts.length + " known virtual hosts has traffic stats</span><br>");
	}
	console.log("</div>");
}

function htmlCluster(cluster, stats, certs) {
	console.log("<div class='cluster'>");
	console.log("<b>" + cluster.name + "</b><br>");
	if (cluster.hosts) {
		for (var host of cluster.hosts) {
			if (host.socket_address) {
				console.log("  => " + host.socket_address.address + ":" + host.socket_address.port_value + "<br>");
		    }
		}
	} else {
		console.log("  => " + cluster.type + "<br>");
	}

	if (cluster.tls_context) {
		htmlCert("CA", cluster.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs, 10);
		// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
		// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
		for (var tlsCertificate of cluster.tls_context.common_tls_context.tls_certificates) {
			htmlCert("chain", tlsCertificate.certificate_chain.filename, certs, 0);
			// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
		}
	}

	if (stats.cluster[cluster.name].upstream_rq_2xx > 0) {
		console.log("  Successful HTTP 2xx " + stats.cluster[cluster.name].upstream_rq_2xx + "<br>");
	} else if (cluster.name.startsWith('inbound|')) {
		console.log("<span class='warning'>WARNING No successful HTTP traffic</span><br>");
	}
	if (stats.cluster[cluster.name].upstream_rq_4xx > 0
			|| stats.cluster[cluster.name].upstream_rq_5xx > 0) {
		console.log("<span class='problem'>ERRORS " + renderBreakdown(stats.cluster[cluster.name], /upstream_rq_([45][0-9][0-9])/) + "</span><br>");
	}
	if (stats.cluster[cluster.name].upstream_cx_connect_fail > 0) {
		console.log("<span class='problem'>CONNECTION FAILURES " + stats.cluster[cluster.name].upstream_cx_connect_fail + "</problem><br>");
	}
	console.log("</div>");
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
		return genHtml(configDump, processStatsData(rawStats, escapes), certs);
	}

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

	genHtml(configDump10, processStatsData(rawStats, escapes), certs);
}

function htmlBootstrap(bootstrap) {
	console.log('<span class="envoy">Istio version: ' + bootstrap.bootstrap.node.metadata.ISTIO_VERSION + "</span><br>");
	console.log("<span class='envoy'>Envoy version: " + bootstrap.bootstrap.node.build_version + "</span><br>");
	console.log();
}

function allListeners(configDump) {
	if (configDump.configs.listeners && configDump.configs.listeners.dynamic_active_listeners) {
		return configDump.configs.listeners.dynamic_active_listeners
			.map(function(l) { return l.listener; });
	}

	return [];
}

function routesByName(configDump) {
	var retval = {};
	if (configDump.configs.routes) {
		if (configDump.configs.routes.static_route_configs) {
			for (var staticRoute of configDump.configs.routes.static_route_configs) {
				retval[staticRoute.route_config.name] = staticRoute.route_config;
			}
		}
		if (configDump.configs.routes.dynamic_route_configs) {
			for (var dynamicRoute of configDump.configs.routes.dynamic_route_configs) {
				retval[dynamicRoute.route_config.name] = dynamicRoute.route_config;
			}
		}
	}
	return retval;
}

function clustersByName(configDump) {
	var retval = {};
	if (configDump.configs.clusters) {
		if (configDump.configs.clusters.static_clusters) {
			for (var staticCluster of configDump.configs.clusters.static_clusters) {
				retval[staticCluster.cluster.name] = staticCluster.cluster;
			}
		}
		if (configDump.configs.clusters.dynamic_active_clusters) {
			for (var dynamicCluster of configDump.configs.clusters.dynamic_active_clusters) {
				retval[dynamicCluster.cluster.name] = dynamicCluster.cluster;
			}
		}
	}
	return retval;
}

function showListenerp(listener, stats) {
	return listenerHasTraffic(listener.name, stats) || inboundListener(listener);
}

function referencedRoutes(listener) {
	var retval = [];

	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				if (filter.config.route_config) {
					if (retval.indexOf(filter.config.route_config.name) < 0) {
						retval.push(filter.config.route_config.name);
					}
				}
				if (filter.config.rds) {
					if (retval.indexOf(filter.config.rds.route_config_name) < 0) {
						retval.push(filter.config.rds.route_config_name);
					}
				}
			}
		}
	}

	return retval;
}

function listenerReferencedClusters(listener) {
	var retval = [];

	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.tcp_proxy") {
				retval.push(filter.config.cluster);
			}
		}
	}

	return retval;
}

function routeReferencedClustersWithTraffic(routeConfig, stats) {
	var retval = [];

	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		for (var route of virtualHost.routes) {
			if (clusterHasTraffic(route.route.cluster, stats) || route.route.cluster.startsWith("inbound|")) {
				retval.push(route.route.cluster);
			}
		}
	}

	return retval;
}

function genHtml(configDump, stats, certs) {
	console.log("<!DOCTYPE html>");
	console.log("<html>");
	console.log("<head>");
	console.log("<title>Envistion</title>");
	console.log("<link rel='stylesheet' href='genhtml.css'>");
	console.log("</head>");
	console.log("<body>");

	htmlBootstrap(configDump.configs.bootstrap);
	
	console.log("<p><table border=1 frame=hsides rules=rows>")
	console.log("<tr><th align='center'>Listeners</th><th align='center'>Routes</th><th align='center'>Clusters</th></tr>");

	// Listeners we will show on the screen
	var listenerRows = {};
	var visibleListeners = [];
	for (var listener of allListeners(configDump)) {
		if (showListenerp(listener, stats)) {
			listenerRows[listener.name] = visibleListeners.length;
			visibleListeners.push(listener);
		}
	}

	var listenersWithTraffic = 0;
	var inboundListeners = 0;
	// var referencedRoutes = [];
	// var referencedClusters = [];
	var allRoutes = routesByName(configDump);
	var allClusters = clustersByName(configDump);
	var clustersShown = [];

	for (var listener of visibleListeners) {

		console.log('<tr><td valign="middle">');
		htmlListener(listener, stats, certs);
		if (listenerHasTraffic(listener.name, stats)) {
			listenersWithTraffic++;
		}
		if (inboundListener(listener)) {
			inboundListeners++;
		}

		console.log('</td><td valign="middle">');

		var routes = referencedRoutes(listener);
		for (var routeName of routes) {
			var route = allRoutes[routeName];
			console.log("<p>");
			if (route) {
				htmlRoute(route, stats);
			} else {
				console.log("internal error: no route for " + routeName);
			}
		}

		console.log('</td><td valign="middle">');

		var clusters = listenerReferencedClusters(listener);
		for (var routeName of routes) {
			var route = allRoutes[routeName];
			if (route) {
				clusters = clusters.concat(routeReferencedClustersWithTraffic(route, stats));
			} else {
				console.log("internal error: no cluster for " + routeName);
			}
		}
		clusters = Array.from(new Set(clusters));
		
		for (var clusterName of clusters) {
			var cluster = allClusters[clusterName];
			console.log("<p>");
			if (cluster) {
				htmlCluster(cluster, stats, certs);
				clustersShown.push(clusterName);
			} else {
				console.log("internal error: cannot find " + clusterName + " in allClusters");
			}
		}

		console.log("</td></tr>");
	}

	// Now show the clusters that aren't attached to a listener
	console.log('<tr><td valign="middle">');
	console.log('</td><td valign="middle">');
	console.log('</td><td valign="middle">');

	for (var clusterName of Object.keys(allClusters)) {
		if (clustersShown.indexOf(clusterName) < 0 && clusterHasTraffic(clusterName, stats)) {
			var cluster = allClusters[clusterName];
			console.log("<p>");
			htmlCluster(cluster, stats, certs);
			clustersShown.push(clusterName);
		}
	}

	console.log("</td></tr>");

	console.log("</table>")

	if (listenersWithTraffic == 0) {
		console.log("<p><span class='warning'>WARNING: No traffic</span>");
	}

	console.log("</body>");
	console.log("</html>");
}

try {
	main();
} catch (err) {
	process.exit(1);
}
