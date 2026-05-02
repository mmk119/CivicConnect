const { createCorsOptions, getAllowedOrigins } = require('../config/cors');

describe('CORS config', () => {
  test('uses env origins when configured', () => {
    expect(getAllowedOrigins({ CORS_ORIGINS: 'http://a.test, http://b.test' })).toEqual([
      'http://a.test',
      'http://b.test'
    ]);
  });

  test('allows requests with no origin for same-origin and server clients', done => {
    const options = createCorsOptions({ CORS_ORIGINS: 'http://allowed.test' });

    options.origin(undefined, (err, allowed) => {
      expect(err).toBeNull();
      expect(allowed).toBe(true);
      done();
    });
  });

  test('blocks unconfigured origins', done => {
    const options = createCorsOptions({ CORS_ORIGINS: 'http://allowed.test' });

    options.origin('http://blocked.test', err => {
      expect(err).toBeInstanceOf(Error);
      done();
    });
  });
});
