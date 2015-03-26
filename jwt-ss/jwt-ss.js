#! /usr/bin/env node



/*
doron.grinstein@concur.com

jwt-ss.js is a sidecar service that verifies JWT tokens
it assumes that there's a public key in a sub folder called publicKeys
it can handle multiple public keys in the sub folder, so long as one of them corresponds to the private key which
generated the JWT. It watches for changes to the public keys folder and reloads the key when anything changes

OPTIONS:

--port=????
--pub_key_folder=????
if ./config.json is provided, it will take precedence. See the CONFIGURATION section below for more info

 */

var nconf = require('nconf');
var jwt = require('jsonwebtoken');
var fs = require('fs');
var _ = require('lodash');
var express = require('express');


// ------------------------  CONFIGURATION ---------------------------------------------
// if ./config.json has a config fragment, it wins, otherwise
// if the config fragment exists as an environment variable, it wins, otherwise
// configuration is read from the command like (i.e. --foo=bar)
// if none of the above are set, then the default specified below is used as a last resort

nconf.argv().env().file({file: './config.json'});

// DEFAULTS - THESE ARE EASILY OVERRIDDEN AS DESCRIBED ABOVE
// NOT TO BE USED IN PRODUCTION - THEY ARE PROVIDED FOR CONVENIENCE ONLY
nconf.set('pub_key_folder', './publicKeys');
nconf.set('port', '3000');


//------------------------- END CONFIGURATION ------------------------------------------

var publicKeys = [];
function init() {
    populatePublicKeys();
}

// this uses sync functions because we do not want this component to proceed until
// all keys are loaded. this happens once for this long-lived component
function populatePublicKeys() {
    publicKeys = [];
    var pubkeydir = nconf.get('pub_key_folder');
    var keyNames = fs.readdirSync(pubkeydir);

    _(keyNames).any(function (k) {
        try {
            publicKeys.push(fs.readFileSync(pubkeydir + '/' + k));
        }
        catch (e) {
            console.log(e.message);
        } // in case the file was deleted
    });
}


function verifyJwt(token) {
    var decoded = null;
    publicKeys.every(function (key) {
        try {
            decoded = jwt.verify(token, key);
            if (decoded != null) {
                return false;
            }
        } catch (e) {
        }
        return true;
    });
    if (decoded) {
        return decoded;
    }
    else
        return null;
}

init();
fs.watch(nconf.get('pub_key_folder'), populatePublicKeys); // whenever something changes in the public key folder, reload

// todo - investigate if I need to worry about concurrency so when publickey directory changes and verify is executing there's no issue
// I THINK there is no issue - populatePublicKeys is synchronous and node is single threaded


var app = express();
app.get('/verify/:jwt', verify);
app.listen(parseInt(nconf.get('port')));
console.log('app listening on port ' + nconf.get('port'));

function verify(req, res) {
    var token = req.params['jwt'];
    res.json(verifyJwt(token));
}
