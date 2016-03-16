define(function(require) {

    'use strict';

    require('es5-shim');

    describe('auth', function() {

        var auth = require('auth');

        describe('implicit grant flow', function() {
            it('should authenticate on start by default', function() {
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999};

                auth.implicitGrantFlow(options);
                expect(win.location).toMatch(new RegExp('^https://api.mendeley.com/oauth/authorize?.+'));
            });

            it('should NOT authenticate on start if authenticateOnStart: false', function() {
                var win = require('mocks/window')('https:', 'example.com', '/app');
                var options = {win: win, clientId: 9999, authenticateOnStart: false};
                auth.implicitGrantFlow(options);
                expect(win.location.toString()).toEqual('https://example.com/app');
            });

            it('should trigger a redirect on calling authenticate()', function() {
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999, authenticateOnStart: false};

                auth.implicitGrantFlow(options).authenticate();
                expect(win.location).toMatch(new RegExp('^https://api.mendeley.com/oauth/authorize?.+'));
            });

            it('should read the access token from a cookie', function() {
                var win = require('mocks/window')();
                win.document.cookie = 'accessToken=auth';
                var options = {win: win, clientId: 9999};

                var flow = auth.implicitGrantFlow(options);
                expect(flow.getToken()).toEqual('auth');
            });

            it('should read the access token from a URL hash', function() {
                var win = require('mocks/window')('https:', 'example.com', 'app', 'token=auth');
                var options = {win: win, clientId: 9999};

                var flow = auth.implicitGrantFlow(options);
                expect(flow.getToken()).toEqual('auth');
            });

            it('should prefer an access token in the hash over the URL', function() {
                var win = require('mocks/window')('https:', 'example.com', 'app', 'token=hash-auth');
                win.document.cookie = 'accessToken=cookie-auth';
                var options = {win: win, clientId: 9999};

                var flow = auth.implicitGrantFlow(options);
                expect(flow.getToken()).toEqual('hash-auth');
            });

            it('should NOT support refresh token URL', function() {
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999, refreshAccessTokenUrl: '/refresh'};

                var flow = auth.implicitGrantFlow(options);
                expect(flow.refreshToken).toBe(auth.noop);
            });

        });

        describe('auth code flow', function() {

            it('should authenticate on start by default', function() {
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999};

                auth.authCodeFlow(options);
                expect(win.location).toEqual('/login');
            });

            it('should NOT authenticate on start if authenticateOnStart: false', function() {
                var win = require('mocks/window')('https:', 'example.com', '/app');
                var options = {win: win, clientId: 9999, authenticateOnStart: false};

                auth.authCodeFlow(options);
                expect(win.location.toString()).toEqual('https://example.com/app');
            });

            it('should trigger a redirect on calling authenticate()', function() {
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999, authenticateOnStart: false};

                auth.authCodeFlow(options).authenticate();
                expect(win.location).toEqual('/login');
            });

            it('should support using a function to get the auth URL', function() {
                var win = require('mocks/window')();
                var options = {
                  win: win,
                  clientId: 9999,
                  authenticateOnStart: false,
                  apiAuthenticateUrl: function() {
                      return '/login?state=foo';
                  }
               };

                auth.authCodeFlow(options).authenticate();
                expect(win.location).toEqual('/login?state=foo');
            });

            it('should read the access token from a cookie', function() {
                var win = require('mocks/window')();
                win.document.cookie = 'accessToken=auth';
                var options = {win: win, clientId: 9999};

                var flow = auth.authCodeFlow(options);
                expect(flow.getToken()).toEqual('auth');
            });

            it('should NOT read the access token from a URL hash', function() {
                var win = require('mocks/window')('https:', 'example.com', 'app', 'token=auth');
                var options = {win: win, clientId: 9999};

                var flow = auth.authCodeFlow(options);
                expect(flow.getToken()).toEqual('');
            });

            it('should support refresh token URL', function() {
                var ajaxRequest;
                var ajaxSpy = spyOn($, 'ajax').and.returnValue($.Deferred().resolve());
                var win = require('mocks/window')();
                var options = {win: win, clientId: 9999, refreshAccessTokenUrl: '/refresh'};

                var flow = auth.authCodeFlow(options);
                flow.refreshToken();
                expect(ajaxSpy).toHaveBeenCalled();

                ajaxRequest = ajaxSpy.calls.mostRecent().args[0];
                expect(ajaxRequest.url).toBe('/refresh');
            });

        });
    });

});
