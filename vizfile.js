// Licensed Materials - Property of IBM
// (C) Copyright IBM Corp. 2018. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or
// disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
// Copyright 2018 IBM Corporation

"use strict";

var fs = require('fs');
var gen = require('./genhtml');

function main() {
	if (process.argv.length < 5) {
		console.log("Usage: node genhtml.js config_dump.json stats.txt certs.json clusters.txt")
		return 1
	}
	var configDumpName = process.argv[2];
	var statsName = process.argv[3];
	var certsName = process.argv[4];
	var clustersName = process.argv[5] || "";

	fs.readFile(configDumpName, 'utf8', function (err, configDumpData) {
	    if (err) throw err;
	    var configDump = JSON.parse(configDumpData);

		fs.readFile(statsName, 'utf8', function (err, statsData) {
		    if (err) throw err;

			fs.readFile(certsName, 'utf8', function (err, certsData) {
			    if (err) throw err;
			    var certs = JSON.parse(certsData);

			    fs.readFile(clustersName, 'utf8', function (err, endpointsData) {
				    if (err && clustersName != "") { throw err; }
				    gen.processEnvoy11(configDump, statsData, gen.processCertsJson11(certs), gen.processColonText(endpointsData));
			    });
			});
		});
	});

	return 0
}

try {
	main();
} catch (err) {
	process.exit(1);
}
