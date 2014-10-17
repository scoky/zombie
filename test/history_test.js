const assert      = require('assert');
const Browser     = require('../src/zombie');
const { brains }  = require('./helpers');
const { Event }   = require('jsdom').level(3, 'events');
const URL         = require('url');


describe('History', function() {
  let browser;

  before(function() {
    browser = Browser.create();
    return brains.ready();
  });


  before(function() {
    brains.get('/history/boo/', function(req, res) {
      const response = req.query.redirected ? 'Redirected' : 'Eeek!';
      res.send(`<html><title>${response}</title></html>`);
    });

    brains.get('/history/boo', function(req, res) {
      res.redirect(URL.format({ pathname: '/history/boo/', query: req.query }));
    });

    brains.get('/history/redirect', function(req, res) {
      res.redirect('/history/boo?redirected=true');
    });

    brains.get('/history/redirect_back', function(req, res) {
      res.redirect(req.headers.referer);
    });

    brains.get('/history/referer', function(req, res) {
      res.send(`<html><title>${req.headers.referer}</title></html>`);
    });

    brains.get(`/history/referer2`, function(req, res) {
      res.send(`<html><title>${req.headers.referer}</title></html>`);
    });
  });


  describe('URL without path', function() {
    before(function() {
      return browser.visit('/');
    });

    it('should resolve URL', function() {
      browser.assert.url('http://example.com/');
    });
    it('should load page,', function() {
      browser.assert.text('title', 'Tap, Tap');
    });
  });


  describe('new window', function() {
    let window;

    before(function() {
      browser.close();
      window = browser.open();
    });

    it('should start out with one location', function() {
      assert.equal(window.history.length, 1);
      browser.assert.url('about:blank');
    });

    describe('go forward', function() {
      before(function() {
        window.history.forward();
        return browser.wait();
      });

      it('should have no effect', function() {
        assert.equal(window.history.length, 1);
        browser.assert.url('about:blank');
      });
    });

    describe('go backwards', function() {
      before(function() {
        window.history.back();
        return browser.wait();
      });

      it('should have no effect', function() {
        assert.equal(window.history.length, 1);
        browser.assert.url('about:blank');
      });
    });
  });


  describe('history', function() {

    describe('pushState', function() {
      let window;

      before(async function() {
        await browser.visit('/');
        browser.history.pushState({ is: 'start' }, null, '/start');
        browser.history.pushState({ is: 'end' },   null, '/end');
        await browser.wait();
        window = browser.window
      });

      it('should add state to history', function() {
        assert.equal(window.history.length, 3);
      });
      it('should change location URL', function() {
        browser.assert.url('/end');
      });

      describe('go backwards', function() {
        let lastEvent;

        before(function(done) {
          window.document.magic = 123;
          window.addEventListener('popstate', function(event) {
            lastEvent = event;
            done();
          });
          window.history.back();
          browser.wait();
        });

        it('should fire popstate event', function() {
          assert(lastEvent instanceof Event);
        });
        it('should include state', function() {
          assert.equal(lastEvent.state.is, 'start');
        });
        it('should not reload page from same host', function() {
          // Get access to the *current* document
          const document = lastEvent.target.window.browser.document;
          assert.equal(document.magic, 123);
        });
      });

      describe('go forwards', function() {
        let lastEvent;

        before(async function(done) {
          await browser.visit('/');
          browser.history.pushState({ is: 'start' }, null, '/start');
          browser.history.pushState({ is: 'end' },   null, '/end');
          browser.back();
          browser.window.addEventListener('popstate', function(event) {
            lastEvent = event;
            done();
          });
          browser.history.forward();
        });

        it('should fire popstate event', function() {
          assert(lastEvent instanceof Event);
        });
        it('should include state', function() {
          assert.equal(lastEvent.state.is, 'end');
        });
      });
    });

    describe('replaceState', function() {
      let window;

      before(async function() {
        await browser.visit('/');
        browser.history.pushState({ is: 'start' },  null, '/start');
        browser.history.replaceState({ is: 'end' }, null, '/end');
        await browser.wait();
        window = browser.window;
      });

      it('should not add state to history', function() {
        assert.equal(window.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/end');
      });

      describe('go backwards', function() {
        before(function(done) {
          window.addEventListener('popstate', function() {
            window.popstate = true;
            done();
          });
          window.history.back();
          browser.wait();
        });

        it('should change location URL', function() {
          browser.assert.url('http://example.com/');
        });
        it('should fire popstate event', function() {
          assert(window.popstate);
        });
      });
    });


    describe('redirect', function() {
      before(function() {
        return browser.visit('/history/redirect');
      });

      it('should redirect to final destination', function() {
        browser.assert.url('/history/boo?redirected=true');
      });
      it('should pass query parameter', function() {
        browser.assert.text('title', 'Redirected');
      });
      it('should not add location in history', function() {
        assert.equal(browser.history.length, 1);
      });
      it('should indicate last request followed a redirect', function() {
        browser.assert.redirected();
      });
    });


    describe('redirect back', function() {
      before(async function() {
        await browser.visit('/history/boo');
        browser.location = '/history/redirect_back';
        await browser.wait();
      });

      it('should redirect to the previous path', function() {
        browser.assert.url('/history/boo');
      });
      it('should pass query parameter', function() {
        browser.assert.text('title', /Eeek!/);
      });
      it('should not add location in history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should indicate last request followed a redirect', function() {
        browser.assert.redirected();
      });
    });

  });


  describe('location', function() {

    describe('open page', function() {
      before(function() {
        return browser.visit('/history/boo');
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 1);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
      it('should set window location', function() {
        browser.assert.url('/history/boo');
      });
      it('should set document location', function() {
        browser.assert.url('/history/boo');
      });
    });

    describe('open from file system', function() {
      const FILE_URL = encodeURI(`file://${__dirname}/data/index.html`);

      before(function() {
        return browser.visit(FILE_URL);
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 1);
      });
      it('should change location URL', function() {
        browser.assert.url(FILE_URL);
      });
      it('should load document', function() {
        const title = browser.html('title');
        assert(~title.indexOf('Insanely fast, headless full-stack testing using Node.js'));
      });
      it('should set window location', function() {
        assert.equal(browser.window.location.href, FILE_URL);
      });
      it('should set document location', function() {
        assert.equal(browser.document.location.href, FILE_URL);
      });
    });

    describe('change pathname', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.location.pathname = '/history/boo';
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });

    describe('change relative href', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.location.href = '/history/boo';
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });

    describe('change hash', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.document.body.innerHTML = '<html><body>Wolf</body></html>';
        browser.window.addEventListener('hashchange', ()=> done());
        browser.window.location.hash = 'boo';
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/#boo');
      });
      it('should not reload document', function() {
        browser.assert.text('body', /Wolf/);
      });
    });

    describe('assign', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.location.assign('/history/boo');
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });

    describe('replace', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.location.replace('/history/boo');
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should not add page to history', function() {
        assert.equal(browser.history.length, 1);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });

    describe('reload', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.document.innerHTML = 'Wolf';
        browser.reload();
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should not add page to history', function() {
        assert.equal(browser.history.length, 1);
      });
      it('should not change location URL', function() {
        browser.assert.url('http://example.com/');
      });
      it('should reload document', function() {
        browser.assert.text('title', /Tap, Tap/);
      });
    });

    describe('components', function() {
      before(()=> browser.visit('/'));

      it('should include protocol', function() {
        assert.equal(browser.location.protocol, 'http:');
      });
      it('should include hostname', function() {
        assert.equal(browser.location.hostname, 'example.com');
      });
      it('should include port', function() {
        assert.equal(browser.location.port, '');
      });
      it('should include hostname and port', function() {
        assert.equal(browser.location.host, 'example.com');
      });
      it('should include pathname', function() {
        assert.equal(browser.location.pathname, '/');
      });
      it('should include search', function() {
        assert.equal(browser.location.search, '');
      });
      it('should include hash', function() {
        assert.equal(browser.location.hash, '');
      });
    });

    describe('set window.location', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.location = 'http://example.com/history/boo';
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });

    describe('set document.location', function() {
      before(()=> browser.visit('/'));
      before(function(done) {
        browser.window.document.location = 'http://example.com/history/boo';
        browser.once('loaded', ()=> done());
        browser.wait();
      });

      it('should add page to history', function() {
        assert.equal(browser.history.length, 2);
      });
      it('should change location URL', function() {
        browser.assert.url('/history/boo');
      });
      it('should load document', function() {
        browser.assert.text('title', /Eeek!/);
      });
    });
  });


  describe('referer not set', function() {
    before(function() {
      return browser.visit('/history/referer');
    });

    it('should be empty', function() {
      browser.assert.text('title', '');
    });
  });

  describe('referer set', function() {
    before(function() {
      return browser.visit('/history/referer', { referer: 'http://braindepot' });
    });

    it('should be set from browser', function() {
      browser.assert.text('title', 'http://braindepot');
    });
  });


  describe('URL with hash', function() {
    before(function() {
      return browser.visit('/#with-hash');
    });

    it('should load page', function() {
      browser.assert.text('title', 'Tap, Tap');
    });
    it('should set location to hash', function() {
      assert.equal(browser.location.hash, '#with-hash');
    });
  });


  after(function() {
    browser.destroy();
  });
});

