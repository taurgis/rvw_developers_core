'use strict';

var Response = require('dw/system/Response');

// Fallback security key
var SECURITY_KEY = 'MY_SECRET';

/**
 * Checks if basic authorization is on, if not check that the SECURITY_KEY is passed in the request URL. If not
 * return false.
 *
 * @return {boolean} - Return if the request is secured in some way.
 */
function checkIfSecured() {
    var basicAuthHeader = request.httpHeaders.get('x-is-authorization');
    var requestQueryString = request.httpQueryString;

    if(!empty(basicAuthHeader) || (requestQueryString && (requestQueryString.indexOf(SECURITY_KEY) >= 0))) {
        // Save it to the session so you don't need to pass on the secret query string to the run.
        session.custom.consoleAllowed = true;
        return true;
    } else {
        return false;
    }
}

/**
 * Checks if the current session has been marked as secure.
 * @return {Boolean} - If the session is secure.
 */
function checkIfSecuredSession() {
    return session.custom.consoleAllowed === true;
}

/**
 * Adds security headers to the response
 */
function addSecurityHeaders() {
    response.setHttpHeader(Response.CONTENT_SECURITY_POLICY, 'frame-ancestors \'self\'');
    response.setHttpHeader(Response.X_CONTENT_TYPE_OPTIONS, 'nosniff');
    response.setHttpHeader(Response.X_XSS_PROTECTION, '1; mode=block');
    response.setHttpHeader(Response.REFERRER_POLICY, 'origin');
    response.setHttpHeader(Response.X_FRAME_OPTIONS, 'SAMEORIGIN');
}

module.exports = {
    SECURITY_KEY: SECURITY_KEY,
    checkIfSecuredSession: checkIfSecuredSession,
    checkIfSecured: checkIfSecured,
    addSecurityHeaders: addSecurityHeaders
}
