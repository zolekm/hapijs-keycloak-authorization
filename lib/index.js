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
    "config": Joi.object().keys({
        "realm": Joi.string().required(),
        "realm-public-key": Joi.string(),
        "auth-server-url": Joi.string().required(),
        "ssl-required": Joi.string(),
        "resource": Joi.string(),
        "credentials": Joi.object().keys({
            "secret": Joi.string()
        }),
        "public-client": Joi.boolean().default(false),
        "context":Joi.string().default('auth')
    }).required(),
    "keepAlive": Joi.boolean().default(false),
    "validateFunc": Joi.func().required()
}).required();

internals.implementation = function (server, options) {

    const results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    const scheme = {
        authorize: function (request, reply) {

            const validate = function () {

                // Check token

                const token = request.headers['authorization'];
                if (!token) {
                    return unauthorized(Boom.unauthorized(null, 'Token Not Found'));
                }

                settings.validateFunc(request, token, results.config, (err, isValid, credentials) => {

                    if (err || !isValid) {
                        return unauthorized(Boom.unauthorized('Token Is Not Valid'));
                    }

                    if (settings.keepAlive) {
                        reply.state(settings.token, token);
                    }

                    return reply.continue({ credentials: credentials || token, artifacts: credentials || token });
                });
            };

            const unauthorized = function (err) {

                return reply(err, null);
            };

            validate();
        }
    };

    return scheme;
};