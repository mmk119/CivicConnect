const jwt = require('jsonwebtoken');
const {
  createAuthenticateToken,
  getCookieValue,
  requireAdmin,
  requireNgo,
  requireVolunteer
} = require('../middleware/auth');

function mockResponse() {
  const res = {};
  res.statusCode = null;
  res.body = null;
  res.sendStatus = jest.fn(code => {
    res.statusCode = code;
    return res;
  });
  res.status = jest.fn(code => {
    res.statusCode = code;
    return res;
  });
  res.json = jest.fn(body => {
    res.body = body;
    return res;
  });
  return res;
}

describe('auth middleware', () => {
  test('rejects missing bearer token', () => {
    const req = { headers: {} };
    const res = mockResponse();
    const next = jest.fn();

    createAuthenticateToken(jwt, 'secret')(req, res, next);

    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('accepts a valid bearer token and attaches user', () => {
    const token = jwt.sign({ user_id: 7, role: 'Volunteer' }, 'secret');
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = mockResponse();
    const next = jest.fn();

    createAuthenticateToken(jwt, 'secret')(req, res, next);

    expect(req.user.user_id).toBe(7);
    expect(req.user.role).toBe('Volunteer');
    expect(next).toHaveBeenCalled();
  });

  test('accepts a valid auth cookie and attaches user', () => {
    const token = jwt.sign({ user_id: 9, role: 'Admin' }, 'secret');
    const req = { headers: { cookie: `theme=dark; cc_token=${encodeURIComponent(token)}` } };
    const res = mockResponse();
    const next = jest.fn();

    createAuthenticateToken(jwt, 'secret')(req, res, next);

    expect(req.user.user_id).toBe(9);
    expect(req.user.role).toBe('Admin');
    expect(next).toHaveBeenCalled();
  });

  test('reads named cookies from a cookie header', () => {
    expect(getCookieValue('a=1; cc_token=abc%20123; theme=dark', 'cc_token')).toBe('abc 123');
  });

  test('role guards reject the wrong role', () => {
    const res = mockResponse();
    const next = jest.fn();

    requireAdmin({ user: { role: 'Volunteer' } }, res, next);
    expect(res.status).toHaveBeenCalledWith(403);

    requireNgo({ user: { role: 'NGO' } }, mockResponse(), next);
    expect(next).not.toHaveBeenCalled();
  });

  test('volunteer guard accepts volunteers', () => {
    const res = mockResponse();
    const next = jest.fn();

    requireVolunteer({ user: { role: 'Volunteer' } }, res, next);

    expect(next).toHaveBeenCalled();
  });
});
