const request = require('supertest');

const runIntegration = process.env.RUN_INTEGRATION_TESTS === 'true';
const describeIntegration = runIntegration ? describe : describe.skip;

describeIntegration('CivicConnect core flows', () => {
  test('login, create opportunity, apply, accept, confirm attendance, feedback, and admin moderation flow', async () => {
    const app = require('../server');
    // Requires local DB migrations and seed data:
    // RUN_INTEGRATION_TESTS=true npm test -- --runInBand
    const ngoLogin = await request(app)
      .post('/api/login')
      .send({ email: 'ngo.cedar.test@civicconnect.local', password: 'Test12345!' });
    expect(ngoLogin.status).toBe(200);
    expect(ngoLogin.body.token).toBeTruthy();

    const volunteerLogin = await request(app)
      .post('/api/login')
      .send({ email: 'volunteer.rana.test@civicconnect.local', password: 'Test12345!' });
    expect(volunteerLogin.status).toBe(200);
    expect(volunteerLogin.body.token).toBeTruthy();

    const adminLogin = await request(app)
      .post('/api/login')
      .send({ email: 'admin.test@civicconnect.local', password: 'Test12345!' });
    expect(adminLogin.status).toBe(200);
    expect(adminLogin.body.token).toBeTruthy();

    const ngoToken = ngoLogin.body.token;
    const volunteerToken = volunteerLogin.body.token;
    const adminToken = adminLogin.body.token;
    const stamp = Date.now();

    const createOpportunity = await request(app)
      .post('/api/opportunities/ins')
      .set('Authorization', `Bearer ${ngoToken}`)
      .send({
        title: `Integration Cleanup ${stamp}`,
        field: 'Environment',
        description: 'A test opportunity created by the integration suite.',
        start_date: '2099-05-01',
        end_date: '2099-05-07',
        schedule_days: ['MON', 'WED'],
        start_time: '09:00',
        end_time: '11:00',
        capacity: 5,
        location: 'Beirut',
        application_questions: ['Why do you want to help?', 'Which days can you attend?']
      });
    expect(createOpportunity.status).toBe(201);
    const opportunityId = createOpportunity.body.id;

    const apply = await request(app)
      .post('/api/applications')
      .set('Authorization', `Bearer ${volunteerToken}`)
      .send({
        opportunity_id: opportunityId,
        application_answers: ['I care about clean public spaces.', 'Monday and Wednesday.']
      });
    expect(apply.status).toBe(201);
    const applicationId = apply.body.application_id;

    const accept = await request(app)
      .patch(`/api/applications/${applicationId}`)
      .set('Authorization', `Bearer ${ngoToken}`)
      .send({ status: 'accepted' });
    expect(accept.status).toBe(200);

    const attendance = await request(app)
      .patch(`/api/applications/${applicationId}/attendance`)
      .set('Authorization', `Bearer ${ngoToken}`)
      .send({ hours_completed: 4 });
    expect(attendance.status).toBe(200);

    const opportunityFeedback = await request(app)
      .post(`/api/feedback/opportunity/${applicationId}`)
      .set('Authorization', `Bearer ${volunteerToken}`)
      .send({
        rating: 2,
        comment: 'Integration test feedback for admin moderation.',
        impact_story: 'This should be deletable by admin.'
      });
    expect(opportunityFeedback.status).toBe(200);

    const feedbackList = await request(app)
      .get('/api/admin/feedback?type=opportunity&search=Integration%20Cleanup')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(feedbackList.status).toBe(200);
    expect(feedbackList.body.length).toBeGreaterThan(0);

    const feedbackId = feedbackList.body[0].feedback_id;
    const review = await request(app)
      .patch(`/api/admin/feedback/opportunity/${feedbackId}/review`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(review.status).toBe(200);

    const deleteFeedback = await request(app)
      .delete(`/api/admin/feedback/opportunity/${feedbackId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(deleteFeedback.status).toBe(200);
  });
});
