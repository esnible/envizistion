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
			if (activeListener.listener.name) {
				retval.push(activeListener.listener.name);
			}
			if (statPrefixTcp(activeListener.listener)) {
				retval.push(statPrefixTcp(activeListener.listener));
			}
			if (statPrefixHttp(activeListener.listener)) {
				retval.push(statPrefixHttp(activeListener.listener));
			}
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

// endpoints data is a string of lines; each line has a format like
// "inbound|9080||productpage.default.svc.cluster.local::127.0.0.1:9080::cx_active::0"
function processColonText(endpointsData) {
	if (!endpointsData) return {};

	var retval = {}
	var lines = endpointsData.split("\n");
	lines.forEach(function(line) {
		if (line == "") return;
		var keyVal = line.split("::");
		var traversal = keyVal.slice(0, -1);
		var subval = retval, prevSubval, prevKey;
		traversal.forEach(function(key) {
			var newSubval = subval[key];
			if (!newSubval) {
				newSubval = {};
				subval[key] = newSubval;
			}
			prevSubval = subval;
			subval = newSubval;
			prevKey = key;
		});
		var val = keyVal[keyVal.length-1];
		try {
			var v = parseInt(keyVal[keyVal.length-1]);
			if (!(isNaN(v))) {
				val = v;
			}
		} catch (err) {
			// do nothing; keep string
		}
		prevSubval[prevKey] = val;
	});
	return retval;
}

// statsData is a string of lines, each line has a format like
// "cluster.inbound|9080||details.default.svc.cluster.local.external.upstream_rq_2xx: 6"
// but because the periods that are part of cluster and listener names aren't escaped we
// can process this by splitting on "."
function processDottedText(statsData, dontBreaks) {
	var retval = {}
	var lines = statsData.split("\n");
	var reversedEscapes = Object.keys(dontBreaks)
		.reduce(function(accum, key) { accum[dontBreaks[key]] = key; return accum; }, {});
	lines.forEach(function(line) {
		line = escapeLine(line, dontBreaks);
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

function clusterHasTraffic(clusterName, stats, clusterDefs, outMsgs) {
	var clusterStats = stats.cluster[clusterName];
	if (clusterStats) {
		return clusterStats.upstream_rq_2xx > 0
		|| clusterStats.upstream_rq_3xx > 0
		|| clusterStats.upstream_rq_4xx > 0
		|| clusterStats.upstream_rq_5xx > 0
		|| clusterStats.upstream_cx_connect_fail > 0
		|| clusterStats.upstream_cx_total > 0;
	}

	// Sometimes the cluster is not referenced in :15000/stats but is in :15000/clusters
	// I am not sure why
	var endpointStats = clusterDefs[clusterName];
	if (endpointStats) {
		for (var candidateHostPort of Object.keys(endpointStats)) {
			// endPointStats will have things like
			// prometheus_stats::127.0.0.1:15000::cx_total::1
			// We are looking for entries of the form <cluster>.<anything>.cx_total
			if (endpointStats[candidateHostPort].cx_total > 0
				|| endpointStats[candidateHostPort].cx_connect_fail > 0) {
				return true;
			}
		}
	}
	
	// happens if no K8s Service references pod (or subset created after pod?)
	// (Also happens for BlueCompute on Istio 1.1, and it happens a lot, so I am suppressing for now.)
	// outMsgs.push("<span class='warning'>warning no stats for cluster " + clusterName + "</span><br>");
	return false; // should never happen, might happen if there is a stats/config mismatch
}

function statPrefixHttp(listener) {
	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				return filter.config.stat_prefix;
			}
		}
	}

	return null;
}

function statPrefixHttp(listener) {
	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				if (filter.typed_config) {
					return filter.typed_config.stat_prefix;
				}
				return filter.config.stat_prefix;
			}
		}
	}

	return null;
}

function statPrefixTcp(listener) {
	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.tcp_proxy") {
				if (filter.typed_config) {
					return filter.typed_config.stat_prefix;
				}
				return filter.config.stat_prefix;
			}
		}
	}

	return null;
}

function statsForListener(listener, stats) {
	var tcpPrefix = statPrefixTcp(listener);
	if (tcpPrefix && stats.tcp && stats.tcp[tcpPrefix]) {
		return stats.tcp[tcpPrefix];
	}
	var httpPrefix = statPrefixHttp(listener);
	if (httpPrefix && stats.http && stats.http[httpPrefix]) {
		return stats.http[httpPrefix];
	}
	return {};
}

function listenerHasTraffic(listener, stats, clusterDefs, allRoutes, allClusters) {
	var lstats = statsForListener(listener, stats);
	if ("downstream_cx_total" in lstats) {
		return lstats.downstream_cx_total > 0;
	}

	// If the listener does not have stats from :15000/stats see if it
	// is connected to any clusters with traffic
	for (var routeName of referencedRoutes(listener)) {
		var route = allRoutes[routeName];
		if (route) {
			if (routeReferencedClustersWithTraffic(route, stats, clusterDefs, allClusters, []).length > 0) {
				return true;
			}
		}
	}
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
	console.log("<b>" + listener.name + "</b><br>");

	if (listener.listener_filters) {
		// This is typically the envoy.listener.tls_inspector
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/listener_filters/tls_inspector#config-listener-filters-tls-inspector
		console.log("-  Filters: " + listener.listener_filters.map(function(lf) { return lf.name; }).join(", ") + "<br>");
	}

	var trafficExpected = true;
	var authnShown = false;
	for (var filterChain of listener.filter_chains) {

		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				var config = (filter.typed_config) ? filter.typed_config : filter.config;
				if (Array.isArray(config.http_filters)) {
					for (var httpFilter of config.http_filters) {
						if (httpFilter.name == "istio_authn") {
							if (!authnShown) {
								if (httpFilter.config && httpFilter.config.policy && Array.isArray(httpFilter.config.policy.peers)) {
									for (var peer of httpFilter.config.policy.peers) {
										console.log("- Istio Authn: " + JSON.stringify(peer))
									}
								}
								authnShown = true;
							}
						} else if (httpFilter.name == "mixer") {
							// Ignore mixer configuration
							// console.log("-  UNSUPPORT DUMP for mixer http_filter which has config keys " + Object.keys(httpFilter.config) + "<br>");
						} else if (httpFilter.name == "envoy.cors") {
							if (httpFilter.config) {
								console.log("-  configured CORS<br>");
							}
						} else if (httpFilter.name == "envoy.router") {
							if (httpFilter.config) {
								console.log("-  configured router<br>");
							}
						} else if (httpFilter.name == "envoy.fault") {
							if (httpFilter.config) {
								console.log("-  configured fault<br>");
							}
						} else {
							console.log("-  UNSUPPORT DUMP for http_filter type name: " + httpFilter.name + " which has keys " + Object.keys(httpFilter) + "<br>");
						}
					}
				}
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

	var listenerStats = statsForListener(listener, stats);
	if (listenerStats) {
		if (listenerStats.downstream_rq_2xx > 0) {
			console.log("  Successful HTTP 2xx " + listenerStats.downstream_rq_2xx + "<br>");
		} else if (listener.name != "virtual") {
			if (!authnShown) {
				console.log("  <span class='warning'>Warning no successful HTTP</span><br>");
			}
		}
		if (listenerStats.downstream_rq_4xx > 0
				|| listenerStats.downstream_rq_5xx > 0) {
			console.log("<span class='problem'>ERRORS " + renderBreakdown(listenerStats, /downstream_rq_([45]..)/) + "</span><br>");
		}
	}

	if (stats.listener && stats.listener[listener.name] && stats.listener[listener.name].ssl) {
		console.log("  SSL handshakes: " + stats.listener[listener.name].ssl.handshake + "<br>");
		if (stats.listener[listener.name].ssl.connection_error) {
			console.log("<span class='problem'>SSL connection errors: " + stats.listener[listener.name].ssl.connection_error + "</span><br>");
		}
	} else if (!listenerStats && trafficExpected) {
		console.log("  <span class='warning'>WARNING: No SSL or HTTP traffic stats</span><br>");
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

function unknownCluster(clusterName, allClusters) {
	return !allClusters[clusterName];
}

function htmlRoute(routeConfig, stats, clusterDefs, allClusters, outMsgs) {
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
			if (clusterHasTraffic(route.route.cluster, stats, clusterDefs, outMsgs)
					|| route.route.cluster.startsWith("inbound|")
					|| unknownCluster(route.route.cluster, allClusters)) {
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

				if (unknownCluster(route.route.cluster, allClusters)) {
					outMsgs.push("<span class='problem'>Route " + routeConfig.name + " refers to non-existent cluster " + route.route.cluster + "</span><br>");
				}
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
	} else if (cluster.type) {
		console.log("  => " + cluster.type + "<br>");
	}

	if (cluster.tls_context) {
		if (cluster.tls_context.sni) {
			console.log("=>SNI: <b>" + cluster.tls_context.sni + "</b><br>");
		}
		htmlCert("CA", cluster.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs, 10);
		// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
		// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
		for (var tlsCertificate of cluster.tls_context.common_tls_context.tls_certificates) {
			htmlCert("chain", tlsCertificate.certificate_chain.filename, certs, 0);
			// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
		}
	}

	if (!(cluster.name in stats.cluster)) {
		// e.g. "outbound|15443||non.existent.cluster"
		stats.cluster[cluster.name] = {};
	}
	if (stats.cluster[cluster.name].upstream_rq_2xx > 0) {
		console.log("  Successful HTTP 2xx " + stats.cluster[cluster.name].upstream_rq_2xx + "<br>");
// Comment out because we don't expect these if cluster stats turned off
//	} else if (cluster.name.startsWith('inbound|')) {
//		console.log("<span class='warning'>WARNING No successful HTTP traffic</span><br>");
	}
	if (stats.cluster[cluster.name].upstream_rq_3xx > 0) {
		console.log("REDIRECTS " + renderBreakdown(stats.cluster[cluster.name], /upstream_rq_(3[0-9][0-9])/) + "<br>");
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

function htmlEndpoint(clusterName, endpointName, endpoint) {
	console.log("<div class='endpoint'>");
	console.log("<b>" + endpointName + "</b><br>");
	console.log(endpoint.health_flags + " " + endpoint.zone + "<br>");
	if (endpoint.rq_timeout > 0) {
		console.log("<span class='problem'>TIMEOUT " + endpoint.rq_timeout + "</span><br>");
	}
	if (endpoint.cx_connect_fail > 0) {
		console.log("<span class='problem'>CONNECT FAIL " + endpoint.cx_connect_fail + "</span><br>");
	}
	if (endpoint.rq_error > 0) {
		console.log("<span class='problem'>ERROR " + endpoint.rq_error + "</span><br>");
	}
	if (endpoint.rq_success == 0) {
		// Sometimes Envoy returns a total that is not the sum of error+success+timeout and success is 0.
		if (endpoint.rq_total == 0) {
			console.log("<span class='warning'>SUCCESS " + endpoint.rq_success + "</span><br>");
		} else {
			console.log("Total " + endpoint.rq_total + "<br>");
		}
	} else {
		console.log("Success " + endpoint.rq_success + "<br>");
	}
	console.log("</div>");
}

function isEndpoint(candidateName) {
	return candidateName.match(/^[1-9]/);
}

function htmlClusterDef(clusterName, clusterDef, cluster, outMsgs) {
	if (typeof clusterDef == 'undefined') return;

	var endpoints = 0;
	for (var candidate of Object.keys(clusterDef)) {
		if (isEndpoint(candidate)) {
			htmlEndpoint(clusterName, candidate, clusterDef[candidate]);
			endpoints++;
		}
	}
	if (endpoints == 0 && cluster.type != "ORIGINAL_DST" && clusterName != "BlackHoleCluster") {
		// outMsgs.push("No endpoints for " + clusterName);
		console.log("<div class='endpoint'>");
		console.log("<span class='warning'>Warning: No endpoints for " + clusterName + "</span><br>");
		console.log("</div>");
	}
}

function inboundListener(listener) {
	for (var filterChain of listener.filter_chains) {
		// If the listener is terminating TLS consider it inbound
		if (filterChain.tls_context) {
			return true;
		}
		// If the listener is connected to filter_chain_match 
		// with server_name *.global consider it inbound
		if (filterChain.filter_chain_match 
				&& filterChain.filter_chain_match.server_names
				&& filterChain.filter_chain_match.server_names.length == 1
				&& filterChain.filter_chain_match.server_names[0] == "*.global") {
			return true;
		}
	}
	return false;
}

function processEnvoy11(configDump, rawStats, certs, clusterDefs) {
	// Is this a Envoy 1.0 format?
	if (configDump.configs.bootstrap) {
		var escapes = escapesFromConfig(configDump);
		return genHtml(configDump, processDottedText(rawStats, escapes), certs,
				clusterDefs);
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

	genHtml(configDump10, processDottedText(rawStats, escapes), certs,
			clusterDefs);
}

function sourceId(configDump) {
	if (configDump.configs.bootstrap.bootstrap.node.id) {
		return configDump.configs.bootstrap.bootstrap.node.id.split('~')[2];
	}
	for (var listener of allListeners(configDump)) {
		for (var filterChain of listener.filter_chains) {
			for (var filter of filterChain.filters) {
				if (filter.name == "envoy.http_connection_manager") {
					if (Array.isArray(filter.config.http_filters)) {
						for (var httpFilter of filter.config.http_filters) {
							if (httpFilter.name == "mixer") {
								return httpFilter.config.transport.attributes_for_mixer_proxy.attributes["source.uid"].string_value;
							}
						}
					}
				}
			}
		}
	}

	return undefined;
}

function htmlIdentity(configDump) {
	var podId = sourceId(configDump);
	if (!podId) {
		return;
	}

	var match = /kubernetes:\/\/(.*)/.exec(podId);
	if (match) {
		podId = match[1];
	}

	console.log("<span class='envoy'>Pod: " + podId + "</span><br>");
}

function htmlBootstrap(bootstrap) {
	if (bootstrap.bootstrap.node.metadata) {
		console.log('<span class="envoy">Istio version: ' + bootstrap.bootstrap.node.metadata.ISTIO_VERSION + "</span><br>");
	}
	console.log("<span class='envoy'>Envoy version: " + bootstrap.bootstrap.node.build_version + "</span><br>");
	console.log();
}

function allListeners(configDump) {
	var retval = [];
	if (configDump.configs.listeners) {
		if (configDump.configs.listeners.dynamic_active_listeners) {
			retval = retval.concat(configDump.configs.listeners.dynamic_active_listeners
					.map(function(l) { return l.listener; }));
		}
		if (configDump.configs.listeners.static_listeners) {
			retval = retval.concat(configDump.configs.listeners.static_listeners
					.map(function(l) { return l.listener; }));
		}
	}

	return retval;
}

function routesByName(configDump) {
	var retval = {};
	if (configDump.configs.routes) {
		if (configDump.configs.routes.static_route_configs) {
			for (var staticRoute of configDump.configs.routes.static_route_configs) {
				if (!staticRoute.route_config.name) {
					// Hack - give name to unnamed routes TODO fix
					staticRoute.route_config.name = staticRoute.route_config.virtual_hosts[0].name;
				}
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

function showListenerp(listener, stats, clusterDefs, allRoutes, allClusters) {
	return listenerHasTraffic(listener, stats, clusterDefs, allRoutes, allClusters) || inboundListener(listener);
}

// referencedRoutes() returns an array of route names
function referencedRoutes(listener) {
	var retval = [];

	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				var config = (filter.typed_config) ? filter.typed_config : filter.config;
				if (config.route_config) {
					if (!config.route_config.name) {
						// Hack - give name to unnamed routes TODO fix
						config.route_config.name = config.route_config.virtual_hosts[0].name;
					}
					if (retval.indexOf(config.route_config.name) < 0) {
						retval.push(config.route_config.name);
					}
				}
				if (config.rds) {
					if (retval.indexOf(config.rds.route_config_name) < 0) {
						retval.push(config.rds.route_config_name);
					}
				}
			}
		}
	}

	return retval;
}

// listenerReferencedClusters() returns a list of cluster names that don't go through routes.
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

function routeReferencedClustersWithTraffic(routeConfig, stats, clusterDefs, allClusters, outMsgs) {
	var retval = [];

	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		for (var route of virtualHost.routes) {
			// If the cluster is inbound show it even if there is no traffic
			var cluster = allClusters[route.route.cluster];
			if (!cluster) {
				outMsgs.push("<span class='warning'>No Envoy definition of cluster " + route.route.cluster + "</span><br>");
				continue;
			}
			var bSocket = cluster.hosts && cluster.hosts.length > 0 && cluster.hosts[0].socket_address;
			if (clusterHasTraffic(route.route.cluster, stats, clusterDefs, outMsgs) 
					|| route.route.cluster.startsWith("inbound|") 
					|| bSocket) {
				retval.push(route.route.cluster);
			}
		}
	}

	return retval;
}

function referencedListeners(configDump, stats, clusterDefs, allRoutes, allClusters) {
	var visibleListeners = [];
	for (var listener of allListeners(configDump)) {
		if (!listener.name) {
			if (listener.address && listener.address.socket_address) {
				// Hack; give name to anonymous listeners (as seen on the Egress) TODO fix
				listener.name = "Anonymous " + listener.address.socket_address.address + "_" + listener.address.socket_address.port_value;
			}
		}
		if (showListenerp(listener, stats, clusterDefs, allRoutes, allClusters)) {
			visibleListeners.push(listener);
		}
	}
	return visibleListeners;
}

function linkEnvoy(listener, route, cluster) {
	if (!listener.clusterLinks) {
		listener.clusterLinks = [];
	}
	if (!listener.clusterReferences) {
		listener.clusterReferences = [];
	}
	if (!listener.routeLinks) {
		listener.routeLinks = [];
	}
	if (route) {
		if (!route.clusterLinks) {
			route.clusterLinks = [];
		}
		if (!route.clusterReferences) {
			route.clusterReferences = [];
		}
	}
	if (cluster) {
		if (!cluster.listenerReferences) {
			cluster.listenerReferences = [];
		}
		if (!cluster.routeReferences) {
			cluster.routeReferences = [];
		}
	}

	if (route) {
		if (cluster.routeLink) {
			if (!(cluster.routeLink === route)) {
				// already "contained" by another route for tree view
				route.clusterReferences.push(cluster);
				cluster.routeReferences.push(route);
			}
		} else {
			cluster.routeLink = route;
			route.clusterLinks = route.clusterLinks.concat(cluster);
		}
	}
	if (cluster) {
		if (cluster.listenerLink) {
			if (!(cluster.listenerLink === listener)) {
				// already "contained" by another listener for tree view
				listener.clusterReferences.push(cluster);
				cluster.listenerReferences.push(listener);
			}
		} else {
			cluster.listenerLink = listener;
			listener.clusterLinks = listener.clusterLinks.concat(cluster);
		}
	}
}

// Mutate data structure linking listener, route, and clusters directly
function linkListeners(configDump, stats, clusterDefs, allClusters, outMsgs) {
	var allRoutes = routesByName(configDump);

	var listeners = referencedListeners(configDump, stats, clusterDefs, allRoutes, allClusters);
	var clustersShown = [];
	for (var listener of listeners) {
		var clusters = listenerReferencedClusters(listener);
		for (var clusterName of clusters) {
			var cluster = allClusters[clusterName];
			if (!cluster) {
				// e.g. "outbound|15443||non.existent.cluster"
				cluster = {name: clusterName, type: ""};
				allClusters[clusterName] = cluster
			}
			linkEnvoy(listener, null, cluster);
			clustersShown.push(clusterName);
		}
		var routes = referencedRoutes(listener);
		for (var routeName of routes) {
			var route = allRoutes[routeName];
			if (route) {
				route.listenerLink = listener;
				var clusters = routeReferencedClustersWithTraffic(route, stats, clusterDefs, allClusters, outMsgs);
				for (var clusterName of clusters) {
					clustersShown.push(clusterName);
					var cluster = allClusters[clusterName];
					linkEnvoy(listener, route, cluster);
				}
			} else {
				console.log("internal error: no cluster for " + routeName);
			}
		}
	}

	// Now create fake "head" listener for clusters that do not have a real one
	var fakeListener = {name: "", filter_chains: []};
	var fakeRoute = {name: ""};
	for (var clusterName of Object.keys(allClusters)) {
		if (clustersShown.indexOf(clusterName) < 0 && clusterHasTraffic(clusterName, stats, clusterDefs, outMsgs)) {
			var cluster = allClusters[clusterName];
			clustersShown.push(clusterName);
			linkEnvoy(fakeListener, fakeRoute, cluster);
		}
	}

	if (fakeListener.clusterLinks && fakeListener.clusterLinks.length) {
		listeners.push(fakeListener);
	}

	return listeners;
}

function genTable(configDump, stats, certs, clusterDefs, outMsgs) {
	console.log("<p><table border=1 frame=hsides rules=rows>")
	console.log("<tr><th align='center'>Listeners</th><th align='center'>Routes</th><th align='center'>Clusters</th><th align='center'>Endpoints</th></tr>");

	var allClusters = clustersByName(configDump);
	var listenerTree = linkListeners(configDump, stats, clusterDefs, allClusters, outMsgs);

	// Filter for clusters that were linked
	var visibleClusters = Object.keys(allClusters).filter(function(clusterName) { return allClusters[clusterName].listenerLink; });
	visibleClusters.sort(function(aName, bName) {
		var a = allClusters[aName], b = allClusters[bName];

		// inbound first, listener name second, route name third, cluster name fourth
		if (inboundListener(a.listenerLink) != inboundListener(b.listenerLink)) {
			return inboundListener(a.listenerLink) ? -1 : 1;
		}
		if (a.listenerLink.name != b.listenerLink.name) {
			if (a.listenerLink.name == "") { return 1; } // sort blank to bottom
			if (b.listenerLink.name == "") { return -1; } // sort blank to bottom
		    return (a.listenerLink.name < b.listenerLink.name) ? -1 : 1;
		}
		if (a.routeLink && b.routeLink && a.routeLink.name != b.routeLink.name) {
		    return (a.routeLink.name < b.routeLink.name) ? -1 : 1;
		}
		if (a.name != b.name) {
		    return (a.name < b.name) ? -1 : 1;
		}
		return 0;
	});

	var inboundListeners = 0;
	var listenersWithTraffic = 0;
	var prevListenerName="##DUMMY", prevRouteName="##DUMMY";
	for (var clusterName of visibleClusters) {
		var cluster = allClusters[clusterName];

		console.log('<tr>');

		if (prevListenerName != cluster.listenerLink.name) {
			console.log('<td valign="middle" rowspan="' + cluster.listenerLink.clusterLinks.length + '">');
			if (cluster.listenerLink.name) {
				for (var listener of cluster.listenerReferences.concat(cluster.listenerLink)) {
					htmlListener(listener, stats, certs);
					if (listenerHasTraffic(listener, stats, clusterDefs, routesByName(configDump), allClusters)) {
						listenersWithTraffic++;
					}
					if (inboundListener(listener)) {
						inboundListeners++;
					}
				}
			}
			console.log('</td>');
			prevListenerName = cluster.listenerLink.name;
		}

		if (cluster.routeLink) {
			if (prevRouteName != cluster.routeLink.name) {
				console.log('<td valign="middle" rowspan="' + cluster.routeLink.clusterLinks.length + '">');
				for (var route of cluster.routeReferences.concat(cluster.routeLink)) {
					htmlRoute(route, stats, clusterDefs, allClusters, outMsgs);
				}
				console.log('</td>');
				prevRouteName = cluster.routeLink.name;
			}
		} else {
			console.log('<td></td>');
		}


		console.log('<td valign="middle">');
		htmlCluster(cluster, stats, certs);
		console.log('</td>');

		console.log('<td valign="middle">');
		htmlClusterDef(clusterName, clusterDefs[clusterName], cluster, outMsgs);
		console.log('</td>');
		console.log("</tr>");
	}

	console.log("</table>")

	if (inboundListeners == 0) {
		outMsgs.push("<p><span class='warning'>WARNING: No inbound listeners</span><br>");
	}
	if (listenersWithTraffic == 0) {
		outMsgs.push("<p><span class='warning'>WARNING: No traffic</span><br>");
	}
}


function genHtml(configDump, stats, certs, clusterDefs) {
	if (!process.env.ENVIZISTION_BODY_ONLY) {
		console.log("<!DOCTYPE html>");
		console.log("<html>");
		console.log("<head>");
		console.log("<title>Envistion</title>");
		console.log("<link rel='stylesheet' href='genhtml.css'>");
		console.log("</head>");
		console.log("<body>");
	}

	htmlIdentity(configDump);
	htmlBootstrap(configDump.configs.bootstrap);

	var outMsgs = [];

	if (!configDump.configs.listeners.dynamic_active_listeners
			&& !configDump.configs.clusters.dynamic_active_clusters) {
		var sid = sourceId(configDump);
		if (sid && sid.indexOf("istio-pilot") < 0) {
			outMsgs.push("<span class='problem'>No dynamic configuration (never contacted Pilot?)</span><br>");
		}
	}

	genTable(configDump, stats, certs, clusterDefs, outMsgs);
	
	// Uniquify
	outMsgs = outMsgs.filter(function(val, i, self) { return self.indexOf(val) === i; });

	for (var outMsg of outMsgs) {
		console.log(outMsg);
	}

	if (!process.env.ENVIZISTION_BODY_ONLY) {
		console.log("</body>");
		console.log("</html>");
	}
}

function captureOutput(func) {
	// TODO Don't do this
	var orig = console.log;
	console.log = func;
	return orig;
}

module.exports.processCertsJson11 = processCertsJson11;  
module.exports.processColonText = processColonText;  
module.exports.processEnvoy11 = processEnvoy11;

// TODO This isn't safe if multiple requests arrive; refactor so processEnvoy11 writes results to caller.
module.exports.captureOutput = captureOutput;  
