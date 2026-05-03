# CivicConnect

CivicConnect is a web platform where approved NGOs post volunteering opportunities and volunteers apply, track applications, receive feedback, and download certificates after confirmed attendance.

## Requirements

- Node.js 18+
- MySQL 8+
- A configured `backend/.env`

## Setup

```powershell
npm install
cd backend
node seed-feedback-test-data.js
cd ..
npm run dev
```

Open:

```text
http://localhost:3000
```

## Environment

Create `backend/.env` from your local values:

```text
PORT=3000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:3000
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=civicconnect
JWT_SECRET=replace_me
JWT_EXPIRES_IN=1h
EMAIL_USER=your_email
EMAIL_APP_PASSWORD=your_gmail_app_password
CLIENT_ID=your_google_client_id
CLIENT_SECRET=your_google_client_secret
REFRESH_TOKEN=your_refresh_token
REDIRECT_URI=https://developers.google.com/oauthplayground
```

Never commit real secrets.

For local email sending, the simplest setup is a Gmail app password in `EMAIL_APP_PASSWORD` with 2-Step Verification enabled on the Gmail account. If you prefer OAuth2, leave `EMAIL_APP_PASSWORD` unset and make sure `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN`, and `REDIRECT_URI` are current. Google returns `invalid_grant` when the refresh token has expired or been revoked, so generate a new refresh token in that case.

## Migrations

Run the migrations in order:

```powershell
cd backend
mysql -u root -p civicconnect < migrations\001_admin_features.sql
mysql -u root -p civicconnect < migrations\002_saved_opportunities.sql
mysql -u root -p civicconnect < migrations\003_feedback_moderation.sql
mysql -u root -p civicconnect < migrations\004_opportunity_schedule.sql
mysql -u root -p civicconnect < migrations\005_matching_questions_moderation_certificates.sql
mysql -u root -p civicconnect < migrations\006_decimal_completed_hours.sql
mysql -u root -p civicconnect < migrations\007_decimal_opportunity_hours.sql
mysql -u root -p civicconnect < migrations\008_profile_feedback_visibility.sql
```

## Test Accounts

Seed data creates:

```text
admin.test@civicconnect.local
ngo.cedar.test@civicconnect.local
ngo.green.test@civicconnect.local
volunteer.maya.test@civicconnect.local
volunteer.karim.test@civicconnect.local
volunteer.rana.test@civicconnect.local
```

Password for all:

```text
Test12345!
```

## Scripts

```powershell
npm start
npm run dev
npm run lint
npm test
```

Integration tests that mutate/read local seeded data are gated:

```powershell
$env:RUN_INTEGRATION_TESTS='true'
npm test
```

## Core Features

- NGO approval by admin
- Opportunity creation, editing, deletion
- Weekday/time scheduling with calculated volunteer hours
- Opportunity-specific applicant review
- Application accept/reject
- Attendance confirmation before or after opportunity date
- Volunteer and NGO feedback
- Admin feedback moderation with review status and reports
- Volunteer availability/preferences and opportunity match badges
- Opportunity application questions and applicant answer review
- Printable volunteer certificates with verification IDs
