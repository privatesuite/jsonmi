const fs = require("fs");
const qs = require("querystring");
const url = require("url");
const body = require("request-body");
const path = require("path");
const http = require("http");
const http2 = require("http2");
const mailee = require("mailee_plugin");
const sha512 = require("js-sha512");
const jsonwebtoken = require("jsonwebtoken");

const log = mailee.utils.log;
const config = mailee.utils.conf();
const secret = config.jsonmi.secret || (Math.random().toString(36).replace("0.", "") + Math.random().toString(36).replace("0.", "") + Math.random().toString(36).replace("0.", "") + Math.random().toString(36).replace("0.", ""));

function validJWT (token) {

	// console.log(token);

	try {

		jsonwebtoken.verify(token, secret);
		return true;

	} catch {

		return false;

	}

}

(async () => {

	if (!config.jsonmi) {

		console.error("Missing configuration options.");
		return;
	
	}
	
	const server = (config.jsonmi.secure ? http2.createSecureServer : http.createServer)({

		ca: config.jsonmi.caPath ? fs.readFileSync(path.join(mailee.constants.basePath, config.jsonmi.caPath)) : undefined,
		key: config.jsonmi.keyPath ? fs.readFileSync(path.join(mailee.constants.basePath, config.jsonmi.keyPath)) : undefined,
		cert: config.jsonmi.certPath ? fs.readFileSync(path.join(mailee.constants.basePath, config.jsonmi.certPath)) : undefined,

	},
	
	/**
	 * 
	 * @param {http.IncomingMessage} req 
	 * @param {http.ServerResponse} res 
	 */
	async function (req, res) {

		// res.writeHead(200, {});

		res.setHeader("Access-Control-Allow-Origin", "*");
		res.setHeader("Access-Control-Allow-Methods", "*");
		res.setHeader("Access-Control-Allow-Headers", req.headers["access-control-request-headers"] || "*");

		if (req.method.toLowerCase() === "options") {

			res.writeHead(200, {

				"Access-Control-Allow-Methods": "GET, POST, OPTIONS"

			});
			// res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
			res.end("GET, POST, OPTIONS");

			return;

		}

		const requestedUrl = url.parse(req.url);
		const query = qs.parse(requestedUrl.query || "") || {};

		if (requestedUrl.pathname === "/auth" || requestedUrl.pathname === "/authenticate") {

			res.writeHead(200, {

				"Content-Type": "application/json"
				
			});

			const result = mailee.smtp.login(query.username, query.password);

			if (!result) res.end(JSON.stringify({

				error: "invalidCredentials",
				message: "Invalid Credentials"

			})); else res.end(JSON.stringify(jsonwebtoken.sign({

				username: query.username

			}, secret)));

			return;

		}

		if (!req.headers["authorization"] || !req.headers["authorization"].startsWith("Bearer ") || !validJWT(req.headers["authorization"].replace("Bearer ", ""))) {

			res.writeHead(403, {

				"Content-Type": "application/json"
				
			});

			res.end(JSON.stringify({

				error: "invalidBearer",
				message: "Invalid Bearer Token"

			}));

			return;

		}

		log.info(`User with token "${req.headers["authorization"]}" requesting ${requestedUrl.pathname}!`);

		const jwt = jsonwebtoken.decode(req.headers["authorization"].replace("Bearer ", ""));

		function me () {

			const me = {...mailee.smtp.users.find(_ => _.username === jwt.username)};

			delete me.password;

			return me;

		}

		if (requestedUrl.pathname === "/send_email") {

			const form = await body(req);

			mailee.smtp.sendEmail("mailee_root", mailee.smtp.sessionRootPassword, {

				to: form.to,
				cc: form.cc,
				bcc: form.bcc,
				subject: form.subject,
				from: !me().name ? `${jwt.username}@${config.smtp.host}` : `${me().name} <${jwt.username}@${config.smtp.host}>`,

				text: form.text,
				html: form.html

			});

			res.writeHead(200, {

				"Content-Type": "application/json"
				
			});

			res.end(JSON.stringify({

				success: "operationSuccessful",
				message: "Operation Successful"

			}));

		} else if (requestedUrl.pathname === "/inbox") {

			const limit = parseInt(query.limit) || 1000;

			log.info(`Looking for emails to "${jwt.username}@${config.smtp.host}"...`);

			// for (const e of (await mailee.database.getEmails())) log.info(e.metadata.to.value.map(_ => _.address));
			const emails = (await mailee.database.getEmails()).filter(_ => (_.metadata.to.value.map(_ => _.address).indexOf(`${jwt.username}@${config.smtp.host}`) !== -1) || (_.metadata.cc ? _.metadata.cc.value.map(_ => _.address).indexOf(`${jwt.username}@${config.smtp.host}`) !== -1 : false) || (_.metadata.bcc ? _.metadata.bcc.value.map(_ => _.address).indexOf(`${jwt.username}@${config.smtp.host}`) !== -1 : false)).slice(0, limit);

			res.writeHead(200, {

				"Content-Type": "application/json"
				
			});

			res.end(JSON.stringify(emails));

		} else if (requestedUrl.pathname === "/email") {

			log.info(`Requesting email ${query.id}...`);

			const email = query.id ? await mailee.database.getEmail(query.id) : false;

			log.info(`Fetched email ${query.id}!`);

			if (email) {

				res.writeHead(200, {

					"Content-Type": "application/json"
					
				});
	
				res.end(JSON.stringify(email));

			} else {

				res.writeHead(404, {

					"Content-Type": "application/json"
					
				});

				res.end(JSON.stringify({

					error: "messageDoesNotExist",
					message: "Message does not exist"

				}));

			}

		} else if (requestedUrl.pathname === "/about_me") {

			res.writeHead(200, {

				"Content-Type": "application/json"
				
			});

			res.end(JSON.stringify(me()));

		} else if (requestedUrl.pathname === "/users") {

			if (me().admin) {

				res.writeHead(200, {

					"Content-Type": "application/json"
					
				});

				res.end(JSON.stringify(mailee.smtp.users.map(__ => {const _ = {...__}; delete _.password; return _})));

			} else {

				res.writeHead(403, {

					"Content-Type": "application/json"
					
				});
	
				res.end(JSON.stringify({
	
					error: "accessForbidden",
					message: "Access Forbidden"
	
				}));

			}

		} else if (requestedUrl.pathname === "/update_user") {

			const form = await body(req);

			if (me().admin || form.username === me().username) {

				if (!form || typeof form.username !== "string" || typeof form.changes !== "object") {

					res.writeHead(400, {

						"Content-Type": "application/json"
						
					});

					res.end(JSON.stringify({

						error: "invalidBody",
						message: "Invalid Body"

					}));

					return;

				}

				if (!form.changes.name) delete form.changes.name;

				if (form.changes.password) form.changes.password = {type: "sha512", value: sha512.sha512(form.changes.password)};
				else delete form.changes.password;

				const user = mailee.smtp.users.findIndex(_ => _.username === form.username);

				if (user === -1 && !form.create) {

					res.writeHead(400, {

						"Content-Type": "application/json"
						
					});

					res.end(JSON.stringify({

						error: "userNotFound",
						message: "User Not Found"

					}));

					return;

				}

				if (!form.delete) mailee.smtp.users.push({...mailee.smtp.users[user], ...form.changes});
				if (user !== -1) mailee.smtp.users.splice(user, 1);
				
				// mailee.smtp.users[user] = {...mailee.smtp.users[user], ...form.changes};

				fs.writeFileSync(path.join(mailee.constants.basePath, mailee.smtp.options.userfile), JSON.stringify(mailee.smtp.users.filter(_ => !_.virtual), null, 2));

				res.writeHead(200, {

					"Content-Type": "application/json"
					
				});

				res.end(JSON.stringify({

					success: "operationSuccessful",
					message: "Operation Successful"
					
				}));

			} else {

				res.writeHead(403, {

					"Content-Type": "application/json"
					
				});
	
				res.end(JSON.stringify({
	
					error: "accessForbidden",
					message: "Access Forbidden"
	
				}));

			}

		} else {

			res.writeHead(404, {

				"Content-Type": "application/json"
				
			});

			res.end(JSON.stringify({

				error: "notFound",
				message: "Route not found"

			}));

		}

	});

	server.listen(config.jsonmi.port || 256, "0.0.0.0", () => {

		log.info(`🚀 JSONMI is listening on http${config.jsonmi.secure ? "s" : ""}://localhost:${config.jsonmi.port || 256}`);

	});

})();
