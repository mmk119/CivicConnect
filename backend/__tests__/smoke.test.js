const request = require('supertest');
const app = require('../server');
const db = require('../db');

describe('CivicConnect smoke tests', () => {
  test('serves the landing page', async () => {
    const response = await request(app).get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('html');
  });

  test('rejects protected requests without a token', async () => {
    const response = await request(app).get('/api/protected');
    expect(response.status).toBe(401);
  });
});

afterAll(async () => {
  await db.end();
});
