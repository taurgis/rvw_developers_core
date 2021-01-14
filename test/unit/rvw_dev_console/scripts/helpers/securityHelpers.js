'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');

require('app-module-path').addPath(process.cwd() + '/cartridges');
require('app-module-path').addPath(process.cwd() + '/test/mocks');

describe('Security Helpers', () => {
    const SecurityHelpers = require('rvw_dev_console/cartridge/scripts/helpers/securityHelpers');
    const Response = require('dw/system/Response');

    describe('Security Headers', function () {
        before(() => {
            global.response = new Response();
            SecurityHelpers.addSecurityHeaders();
        })

        it('Should set security headers.', () => {
            expect(response.containsHttpHeader(Response.CONTENT_SECURITY_POLICY)).to.be.true;
            expect(response.containsHttpHeader(Response.X_CONTENT_TYPE_OPTIONS)).to.be.true;
            expect(response.containsHttpHeader(Response.X_XSS_PROTECTION)).to.be.true;
            expect(response.containsHttpHeader(Response.REFERRER_POLICY)).to.be.true;
            expect(response.containsHttpHeader(Response.X_FRAME_OPTIONS)).to.be.true;
        });

        it('Should have a correct Content Security Policy header.', () => {
            expect(response.getHttpHeader(Response.CONTENT_SECURITY_POLICY)).to.be.equal('frame-ancestors \'self\'');
        });

        it('Should have a correct Content Type Options header.', () => {
            expect(response.getHttpHeader(Response.X_CONTENT_TYPE_OPTIONS)).to.be.equal('nosniff');
        });

        it('Should have a correct XSS Protection header.', () => {
            expect(response.getHttpHeader(Response.X_XSS_PROTECTION)).to.be.equal('1; mode=block');
        });

        it('Should have a correct Referrer Policy header.', () => {
            expect(response.getHttpHeader(Response.REFERRER_POLICY)).to.be.equal('origin');
        });

        it('Should have a correct Frame Options header.', () => {
            expect(response.getHttpHeader(Response.X_FRAME_OPTIONS)).to.be.equal('SAMEORIGIN');
        });
    });

    describe('Secure console', () => {
        var headerGetMock = sinon.stub();

        before(() => {
            global.session = {
                custom: {}
            };

            global.request = {
                httpHeaders: {
                    get: headerGetMock
                },
                httpQueryString: ''
            }

            global.empty = (value) => value == null;
        });

        it('Should export the used fallback security key.', () => {
            expect(SecurityHelpers.SECURITY_KEY).to.not.be.empty;
        });

        describe('Secured request', () => {
            beforeEach(() => {
               headerGetMock.reset();
            });

            it('Should return false when the console is not secured.', () => {
                headerGetMock.returns(null);
                expect(SecurityHelpers.checkIfSecured()).to.be.false;
            });

            it('Should return true when basic authentication is enabled and being used.', () => {
                headerGetMock.returns('Basic xxxxxx');
                expect(SecurityHelpers.checkIfSecured()).to.be.true;
            });

            it('Should return true when basic authentication is disabled, but security key is passed.', () => {
                headerGetMock.returns(null);
                global.request.httpQueryString = SecurityHelpers.SECURITY_KEY;
                expect(SecurityHelpers.checkIfSecured()).to.be.true;
            });

            it('Should mark a session as secure after a security request check has passed.', () => {
                headerGetMock.returns('Basic xxxxxx');
                SecurityHelpers.checkIfSecured();
                expect(SecurityHelpers.checkIfSecuredSession()).to.be.true;
            });
        });

        describe('Secured sessions', () => {

            before(() => {
                global.session.custom.consoleAllowed = false;
            });

            it('Should mark a session as insecure by default.', () => {
                expect(SecurityHelpers.checkIfSecuredSession()).to.be.false;
            });

            it('Should return true if the session is secure.', () => {
                global.session.custom.consoleAllowed = true;
                expect(SecurityHelpers.checkIfSecuredSession()).to.be.true;
            });
        });
    });
});
