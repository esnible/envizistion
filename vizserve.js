// Licensed Materials - Property of IBM
// (C) Copyright IBM Corp. 2018. All Rights Reserved.
// US Government Users Restricted Rights - Use, duplication or
// disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
// Copyright 2018 IBM Corporation

"use strict";

var http = require('http');
var fs = require('fs');
var gen = require('./genhtml');

http.createServer(function (req, res) {
	if (req.url == "/") {
		getEnvoyConfig(function (err, html) {
			if (err) {
				res.write(err.toString());
			}
			if (html) {
				res.write(html)
			}
			res.end(); //end the response
		});
	} else if (req.url == "/genhtml.css") {
		res.end(fs.readFileSync(__dirname + req.url));
	} else {
		console.log("Unexpected url=" + req.url);
		res.writeHead(404);
		res.end(); //end the response
	}
}).listen(15001);

function getEnvoyConfig(func) {
	getData('/config_dump', function (err, configDumpData) {
	    if (err) { func(err, null); return; }
	    var configDump = JSON.parse(configDumpData);

		getData('/stats', function (err, statsData) {
		    if (err) { func(err, null); return; }

			getData('/certs', function (err, certsData) {
			    if (err) { func(err, null); return; }
			    var certs = JSON.parse(certsData);

			    getData('/clusters', function (err, endpointsData) {
				    if (err) { func(err, null); return; }

				    var accum = '';
				    var orig = gen.captureOutput(function (s) {
				    	accum = accum + s;
				    })
				    gen.processEnvoy11(configDump, statsData, gen.processCertsJson11(certs), gen.processColonText(endpointsData));
				    gen.captureOutput(orig);
				    func(null, accum);
			    });
			});
		});
	});
}

function getData(path, func) {
    var body = '';
	var req = http.get({
        host: 'localhost',
        port: 15000,
        path: path
    }, function(response) {
        response.on('data', function(d) {
            body += d;
        });
        response.on('end', function() {
        	func(null, body);
        });
    });
    req.on('error', function(e) {
    	func(e, null);
    })
	return req;
}