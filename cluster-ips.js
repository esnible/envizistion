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

var podScraper = {};

podScraper.configDump = function(name, namespace, callback) {
	// TODO use namespace
	this.parseJSON(this.dirName + "/" + name + "-config_dump.json", callback);
}

podScraper.certs = function(name, namespace, callback) {
	// TODO use namespace
	this.parseJSON(this.dirName + "/" + name + "-certs.json", callback);
}

podScraper.parseJSON = function(filename, callback) {
	fs.readFile(filename, 'utf8', function (err, jsonData) {
	    if (err) {
	    	callback(err, null);
	    } else {
	    	var j = JSON.parse(jsonData);
	    	callback(null, j);
	    }
	});
}

function main() {
	if (process.argv.length != 4) {
		console.log("Usage: node cluster-ips.js <dirname> <start>")
		return 1
	}
	podScraper.dirName = process.argv[2];
	var starter = process.argv[3];

	fs.readFile(podScraper.dirName + "/pods.json", 'utf8', function (err, podsData) {
	    if (err) throw err;
	    var pods = JSON.parse(podsData);
	    clusterAnalyze(pods, starter, podScraper);
	});
	
	return 0
}

function clusterAnalyze(pods, ip, scraper) {
	// pods will have apiVersion,items,kind="List",metadata
	for (var pod of pods.items) {
		// pod will have apiVersion,kind,metadata,spec,status
		// pod.status will have some of conditions,containerStatuses,hostIP,initContainerStatuses,phase,podIP,qosClass,startTime
		// pod.metadata will have some of annotations,creationTimestamp,generateName,labels,name,namespace,ownerReferences,resourceVersion,selfLink,uid
		// console.log("pod.items[i].metadata keys are " + Object.keys(pod.metadata));
		// console.log(pod.metadata.name + " has IP " + pod.status.podIP);
		if (pod.status.podIP == ip) {
			ipAnalyze(ip, pod.metadata.name, pod.metadata.namespace, scraper);
		}
	}
}

function ipAnalyze(ip, name, namespace, scraper) {
	console.log(ip + ", " + name);
	scraper.configDump(name, namespace, function(err, configDump) {
	    if (err) throw err;

		scraper.certs(name, namespace, function (err, certs) {
		    if (err) throw err;

		    // console.log("certs is " + JSON.stringify(certs));
		    for (var listener of allListeners(configDump)) {
		    	// console.log("printing listener " + listener.name);
		    	if (listener.address.socket_address.address == ip || listener.address.socket_address.address == "0.0.0.0") {
			    	printListener(listener, certs, configDump);
			    	/*
			    	for (var route of inboundRoutes(listener)) {
			    		console.log("printing inbound route of " + listener.name);
			    		printRouteMatches(route);
			    	}
			    	*/
			    	/*
			    	var routes = referencedRoutes(listener);
			    	if (routes.length > 0) {
			    		console.log("   routes is " + routes);
			    	}
			    	*/
		    	}
		    }
		});
	});
}

function printListener(listener, certs, configDump) {
	// console.log("listener keys are " + Object.keys(listener));
	// console.log("listener is " + JSON.stringify(listener));
	console.log("Listener");
	// console.log("Listener: " + listener.name);

	if (listener.address.socket_address) {
		console.log("  " + listener.address.socket_address.address + ":" + listener.address.socket_address.port_value);
	}
	if (listener.listener_filters && listener.listener_filters.length==1 && listener.listener_filters[0].name == 'envoy.listener.tls_inspector') {
		console.log("  permissive (both TLS and plaintext)");
	} else if (listener.listener_filters) {
		// This is typically the envoy.listener.tls_inspector
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/listener_filters/tls_inspector#config-listener-filters-tls-inspector
		console.log("  Filters: " + listener.listener_filters.map(function(lf) { return lf.name; }).join(", ") + "");
	}

	var trafficExpected = true;
	for (var filterChain of listener.filter_chains) {
		// console.log("filterChain has keys " + Object.keys(filterChain));
		// TLS ALPN
		if (filterChain.filter_chain_match) {
			if (filterChain.filter_chain_match.application_protocols) {
				console.log("  Application Protocols: " + filterChain.filter_chain_match.application_protocols.join(", "));
			} else {
				console.log("  No Application Protocols: ")
			}
		}
		// TLS Certs
		if (filterChain.tls_context) {
			printCert("CA", filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename, certs, 10);
			// console.log("  CA filename " + filterChain.tls_context.common_tls_context.validation_context.trusted_ca.filename);
			// console.log("  filterChain[i].tls_context.common_tls_context.validation_context.trusted_ca has keys " + Object.keys(filterChain.tls_context.common_tls_context.validation_context.trusted_ca));
			for (var tlsCertificate of filterChain.tls_context.common_tls_context.tls_certificates) {
				printCert("chain", tlsCertificate.certificate_chain.filename, certs, 0);
				// console.log("  Cert Chain filename " + tlsCertificate.certificate_chain.filename);
				// console.log("  filterChain[i].tls_context.common_tls_context.tls_certificates[j].certificate_chain has keys " + Object.keys(tlsCertificate.certificate_chain));
			}
		}
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				if (filter.config.route_config) {
					printRouteMatches(filter.config.route_config);
				}
				if (filter.config.rds) {
					var routeConfig = rdsRouteConfig(filter.config.rds.route_config_name, configDump);
					if (routeConfig) {
						printRouteMatches(routeConfig);
					}
				}
			} else if (filter.name == "mixer") {
				// Ignore filter.config for mixer filters
				console.log("  Uses Istio Mixer");
			} else if (filter.name == "envoy.tcp_proxy") {
				// console.log("-  TCP cluster => " + filter.config.cluster + "");
				console.log("  TCP");
			} else if (filter.name == "envoy.filters.network.sni_cluster") {
				console.log("  Multicluster: Uses SNI name as cluster name");
				trafficExpected = false;
			} else if (filter.name == "envoy.filters.network.tcp_cluster_rewrite") {
				console.log("  Multicluster: Rewrites '" + filter.config.cluster_pattern + "' to '" + filter.config.cluster_replacement + "'");
			} else {
				console.log("  UNSUPPORT DUMP for filter type name: " + filter.name + " which has keys " + Object.keys(filter) + "");
			}
		}
	}

	/*
	var listenerStats = statsForListener(listener, stats);
	if (listenerStats) {
		if (listenerStats.downstream_rq_2xx > 0) {
			console.log("  Successful HTTP 2xx " + listenerStats.downstream_rq_2xx + "");
		} else if (listener.name != "virtual") {
			console.log("  <span class='warning'>Warning no successful HTTP</span><br>");
		}
		if (listenerStats.downstream_rq_4xx > 0
				|| listenerStats.downstream_rq_5xx > 0) {
			console.log("<span class='problem'>ERRORS " + renderBreakdown(listenerStats, /downstream_rq_([45]..)/) + "</span><br>");
		}
	}

	if (stats.listener[listener.name] && stats.listener[listener.name].ssl) {
		console.log("  SSL handshakes: " + stats.listener[listener.name].ssl.handshake + "<br>");
		if (stats.listener[listener.name].ssl.connection_error) {
			console.log("<span class='problem'>SSL connection errors: " + stats.listener[listener.name].ssl.connection_error + "</span><br>");
		}
	} else if (!listenerStats && trafficExpected) {
		console.log("  <span class='warning'>WARNING: No SSL or HTTP traffic stats</span><br>");
	}
	*/
}

function rdsRouteConfig(name, configDump) {
	for (var config of configDump.configs) {

		if (config.static_route_configs) {
			for (var route of config.static_route_configs) {
				if (route.route_config.name == name) {
					return route.route_config;
				}
			}
		}
		if (config.dynamic_route_configs) {
			for (var route of config.dynamic_route_configs) {
				if (route.route_config.name == name) {
					return route.route_config;
				}
			}
		}
	}
	return null;
}

function getCert(certs, filename) {
	var filenames = [];
	for (var cert of certs.certificates) {
		for (var caCert of cert.ca_cert) {
			// keys are path,serial_number,subject_alt_names,days_until_expiration,valid_from,expiration_time
			if (caCert.path == filename) {
				return caCert;
			}
			filenames.push(caCert.path);
		}
		for (var certChain of cert.cert_chain) {
			if (certChain.path == filename) {
				return certChain;
			}
			filenames.push(certChain.path);
		}
	}
	console.log("  WARNING UNKNOWN CERT " + filename + ", names are " + filenames + "");
	return null;
}

function printCert(label, filename, certs, importantDays) {
	// keys are  path,serial_number,subject_alt_names,days_until_expiration,valid_from,expiration_time
	var cert = getCert(certs, filename);
	if (!cert) {
		return;
	}

	console.log("    " + label + " " + filename.split('/').slice(-1)[0] + " " +
			  cert.serial_number + "");
	if (cert.daysLeft < 0) {
		console.log("  EXPIRED");
	} else if (cert.daysLeft < importantDays) {
		console.log("  days until expiration: " + cert.daysLeft + ")");
	}
}

function inboundRoutes(listener) {
	var retval = [];

	for (var filterChain of listener.filter_chains) {
		for (var filter of filterChain.filters) {
			if (filter.name == "envoy.http_connection_manager") {
				if (filter.config.route_config) {
					retval.push(filter.config.route_config);
				}
				// Ignore RDS routes, they are outbound
			}
		}
	}

	return retval;
}

function printRouteMatches(routeConfig) {
	for (var virtualHost of routeConfig.virtual_hosts) {
		var printedDomains = false;
		// See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-route
		for (var route of virtualHost.routes) {
			if (!printedDomains) {
				if (virtualHost.domains.length == 1) {
					console.log("    " + virtualHost.domains[0] + "");
				} else {
					var domain = virtualHost.domains.concat().sort(function(a, b) { return a.length - b.length; }).slice(-1)[0];
					console.log("    " + domain + " etc.");
				}

				printedDomains = true;
			}
			console.log("      " + htmlMatch(route.match) /*+ " => " + route.route.cluster + ""*/);
			if (route.route.host_rewrite) {
				console.log("        (rewritten " + route.route.host_rewrite + ")");
			}
			if (route.per_filter_config) {
				htmlPerFilterConfig(route.per_filter_config);
			}
		}
	}
}

//See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-headermatcher
function htmlMatchHeader(header) {
	if (header.exact_match) {
		return header["name"] + "==" + header.exact_match;
	}

	return JSON.stringify(header);
}

//See https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/route/route.proto#envoy-api-msg-route-routematch
function htmlMatch(match) {
	return Object.keys(match).map(function(key) { return htmlMatchKey(key, match[key]); }).join(" && ");
}

function htmlMatchKey(key, val) {
	if (key == "prefix" || key == "path" || key == "regex") {
		return key + " " + val;
	} else if (key == "headers") {
		return "headers " + val.map(function (header) { return htmlMatchHeader(header); }).join("; ");
	}

	return key + " " + JSON.stringify(val);
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
			console.log("DELAY " + envoyFault.delay.fixed_delay + htmlPercent(envoyFault.delay.percentage) + "");
		} else {
			console.log("FAULT INJECTION " + faultType + "");
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
			console.log(configType + "")
		}
	}
}


function allListeners(configDump) {
	var retval = [];
	for (var config of configDump.configs) {
		// console.log("configDump.configs[] keys are " + Object.keys(config));
		if (config.static_listeners) {
			if (config.static_listeners) {
				retval = retval.concat(config.static_listeners
						.map(function(l) { return l.listener; }));
			}
			if (config.dynamic_active_listeners) {
				retval = retval.concat(config.dynamic_active_listeners
						.map(function(l) { return l.listener; }));
			}
		}
	}
	return retval;
}

try {
	main();
} catch (err) {
	process.exit(1);
}
