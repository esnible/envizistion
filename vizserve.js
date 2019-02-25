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

var http = require('http');
var url = require('url');
var fs = require('fs');
var gen = require('./genhtml');

http.createServer(function (req, res) {
	var parsedUrl = url.parse(req.url, true);
	var queryData = parsedUrl.query;
	if (parsedUrl.pathname == "/") {
		getEnvoyConfig(function (err, html) {
			if (err) {
				res.write(err.toString());
			}
			if (html) {
				res.write(html)
			}
			res.end(); //end the response
		}, queryData.showall != null);
	} else if (parsedUrl.pathname == "/genhtml.css") {
		res.end(fs.readFileSync(__dirname + req.url));
	} else {
		console.log("Unexpected url=" + req.url);
		res.writeHead(404);
		res.end(); //end the response
	}
}).listen(15001);

console.log("Listening on 15001");

// 'func' takes the output
// If showAllClusters, show all clusters not just those with traffic
function getEnvoyConfig(func, showAllClusters) {
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
					gen.processEnvoy11(configDump, 
							statsData,
							gen.processCertsJson11(certs),
							gen.processColonText(endpointsData),
							{showAll: showAllClusters});
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