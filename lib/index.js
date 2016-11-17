'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');

// Declare internals

const internals = {};

exports.register = function (server, options, next) {

    server.auth.scheme('keycloak-authorization', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

internals.schema = Joi.object({
    config: Joi.object().keys({
        "realm": Joi.string(),
        "auth-server-url": Joi.string(),
        "ssl-required": Joi.string(),
        "resource": Joi.string(),
        "credentials": Joi.object().keys({
             "secret": Joi.string()
        })
    }),
    "keepAlive": Joi.boolean().default(false),
    "validateFunc": Joi.func().required()
}).required();

internals.implementation = function (server, options) {

    const results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    const scheme = {
        authenticate: function (request, reply) {

            const validate = function () {

                // Check cookie

                const token = request.headers['Authorization'];
                if (!token) {
                    return unauthenticated(Boom.unauthorized(null, 'Token Not Found'));
                }

                settings.validateFunc(request, token, (err, isValid, credentials) => {

                    if (err ||
                        !isValid) {

                        return unauthenticated(Boom.unauthorized('Invalid cookie'));
                    }

                    if (settings.keepAlive) {
                        reply.state(settings.token, token);
                    }

                    return reply.continue({ credentials: credentials || token, artifacts: credentials || token });
                });
            };

            const unauthenticated = function (err) {

                return reply(err, null);
            };

            validate();
        }
    };

    return scheme;
};