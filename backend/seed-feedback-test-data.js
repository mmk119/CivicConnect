require('dotenv').config();

const bcrypt = require('bcrypt');
const db = require('./db');

const PASSWORD = 'Test12345!';

async function upsertUser(connection, { name, email, role, ngoId = null }) {
    const passwordHash = await bcrypt.hash(PASSWORD, 10);
    const [existing] = await connection.execute(
        'SELECT user_id FROM Users WHERE email = ?',
        [email]
    );

    if (existing.length > 0) {
        const userId = existing[0].user_id;
        await connection.execute(
            `UPDATE Users
             SET name = ?, password_hash = ?, role = ?, Verified = 'YES',
                 account_status = 'active', ngo_id = ?
             WHERE user_id = ?`,
            [name, passwordHash, role, ngoId, userId]
        );
        return userId;
    }

    const [result] = await connection.execute(
        `INSERT INTO Users (name, email, password_hash, role, Verified, account_status, ngo_id)
         VALUES (?, ?, ?, ?, 'YES', 'active', ?)`,
        [name, email, passwordHash, role, ngoId]
    );
    return result.insertId;
}

async function upsertVolunteer(connection, userId, { phone, city, skills, interests, experiences, dob }) {
    const [existing] = await connection.execute(
        'SELECT volunteer_id FROM Volunteers WHERE user_id = ?',
        [userId]
    );

    if (existing.length > 0) {
        const volunteerId = existing[0].volunteer_id;
        await connection.execute(
            `UPDATE Volunteers
             SET phone = ?, city = ?, skills = ?, interests = ?, experiences = ?, Date_of_Birth = ?
             WHERE volunteer_id = ?`,
            [phone, city, skills, interests, experiences, dob, volunteerId]
        );
        return volunteerId;
    }

    const [result] = await connection.execute(
        `INSERT INTO Volunteers (user_id, phone, city, skills, interests, experiences, Date_of_Birth)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, phone, city, skills, interests, experiences, dob]
    );
    return result.insertId;
}

async function upsertNgo(connection, userId, { name, description, address, status }) {
    const [existing] = await connection.execute(
        'SELECT ngo_id FROM NGOs WHERE user_id = ?',
        [userId]
    );

    if (existing.length > 0) {
        const ngoId = existing[0].ngo_id;
        await connection.execute(
            `UPDATE NGOs
             SET name = ?, description = ?, address = ?, approval_status = ?, rejection_reason = NULL
             WHERE ngo_id = ?`,
            [name, description, address, status, ngoId]
        );
        await connection.execute('UPDATE Users SET ngo_id = ? WHERE user_id = ?', [ngoId, userId]);
        return ngoId;
    }

    const [result] = await connection.execute(
        `INSERT INTO NGOs (name, description, address, approval_status, user_id)
         VALUES (?, ?, ?, ?, ?)`,
        [name, description, address, status, userId]
    );
    await connection.execute('UPDATE Users SET ngo_id = ? WHERE user_id = ?', [result.insertId, userId]);
    return result.insertId;
}

async function upsertOpportunity(connection, ngoId, opportunity) {
    const [existing] = await connection.execute(
        'SELECT opportunity_id FROM Opportunities WHERE ngo_id = ? AND title = ?',
        [ngoId, opportunity.title]
    );

    if (existing.length > 0) {
        const opportunityId = existing[0].opportunity_id;
        await connection.execute(
            `UPDATE Opportunities
             SET field = ?, description = ?, start_date = ?, end_date = ?,
                 schedule_days = ?, start_time = ?, end_time = ?,
                 hours_required = ?, capacity = ?, location = ?
             WHERE opportunity_id = ?`,
            [
                opportunity.field,
                opportunity.description,
                opportunity.startDate,
                opportunity.endDate,
                opportunity.scheduleDays,
                opportunity.startTime,
                opportunity.endTime,
                opportunity.hours,
                opportunity.capacity,
                opportunity.location,
                opportunityId
            ]
        );
        return opportunityId;
    }

    const [result] = await connection.execute(
        `INSERT INTO Opportunities
            (title, field, description, start_date, end_date, schedule_days, start_time, end_time, hours_required, capacity, location, ngo_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            opportunity.title,
            opportunity.field,
            opportunity.description,
            opportunity.startDate,
            opportunity.endDate,
            opportunity.scheduleDays,
            opportunity.startTime,
            opportunity.endTime,
            opportunity.hours,
            opportunity.capacity,
            opportunity.location,
            ngoId
        ]
    );
    return result.insertId;
}

async function upsertApplication(connection, { volunteerId, opportunityId, status, confirmed, hours }) {
    const [existing] = await connection.execute(
        'SELECT application_id FROM Applications WHERE volunteer_id = ? AND opportunity_id = ?',
        [volunteerId, opportunityId]
    );

    const attendance = confirmed ? 'YES' : 'NO';
    const confirmedAt = confirmed ? new Date() : null;

    if (existing.length > 0) {
        const applicationId = existing[0].application_id;
        await connection.execute(
            `UPDATE Applications
             SET status = ?, attendance_confirmed = ?, hours_completed = ?, attendance_confirmed_at = ?
             WHERE application_id = ?`,
            [status, attendance, hours, confirmedAt, applicationId]
        );
        return applicationId;
    }

    const [result] = await connection.execute(
        `INSERT INTO Applications
            (volunteer_id, opportunity_id, status, attendance_confirmed, hours_completed, attendance_confirmed_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [volunteerId, opportunityId, status, attendance, hours, confirmedAt]
    );
    return result.insertId;
}

async function upsertOpportunityFeedback(connection, feedback) {
    await connection.execute(
        `INSERT INTO OpportunityFeedback
            (application_id, volunteer_id, opportunity_id, rating, comment, impact_story)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            rating = VALUES(rating),
            comment = VALUES(comment),
            impact_story = VALUES(impact_story),
            updated_at = CURRENT_TIMESTAMP`,
        [
            feedback.applicationId,
            feedback.volunteerId,
            feedback.opportunityId,
            feedback.rating,
            feedback.comment,
            feedback.impactStory
        ]
    );
}

async function upsertVolunteerFeedback(connection, feedback) {
    await connection.execute(
        `INSERT INTO VolunteerFeedback
            (application_id, ngo_id, volunteer_id, rating, endorsement_title, comment, strengths)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            rating = VALUES(rating),
            endorsement_title = VALUES(endorsement_title),
            comment = VALUES(comment),
            strengths = VALUES(strengths),
            updated_at = CURRENT_TIMESTAMP`,
        [
            feedback.applicationId,
            feedback.ngoId,
            feedback.volunteerId,
            feedback.rating,
            feedback.title,
            feedback.comment,
            feedback.strengths
        ]
    );
}

async function main() {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        await upsertUser(connection, {
            name: 'CivicConnect Test Admin',
            email: 'admin.test@civicconnect.local',
            role: 'Admin'
        });

        const ngoUserA = await upsertUser(connection, {
            name: 'Cedar Relief Coordinator',
            email: 'ngo.cedar.test@civicconnect.local',
            role: 'NGO'
        });
        const ngoA = await upsertNgo(connection, ngoUserA, {
            name: 'Cedar Relief Collective',
            description: 'A Beirut-based NGO focused on food support, crisis response, and neighborhood resilience.',
            address: 'Hamra, Beirut',
            status: 'approved'
        });

        const ngoUserB = await upsertUser(connection, {
            name: 'Green Steps Coordinator',
            email: 'ngo.green.test@civicconnect.local',
            role: 'NGO'
        });
        const ngoB = await upsertNgo(connection, ngoUserB, {
            name: 'Green Steps Lebanon',
            description: 'Environmental action group organizing cleanups, awareness workshops, and recycling drives.',
            address: 'Mar Mikhael, Beirut',
            status: 'approved'
        });

        const volunteerUserA = await upsertUser(connection, {
            name: 'Maya Haddad',
            email: 'volunteer.maya.test@civicconnect.local',
            role: 'Volunteer'
        });
        const volunteerA = await upsertVolunteer(connection, volunteerUserA, {
            phone: '+961 70 111 222',
            city: 'Beirut',
            skills: 'Teaching, Event planning, Arabic, English',
            interests: 'Education, Food Distribution, Community',
            experiences: 'Tutored children for a community center, helped organize a donation drive',
            dob: '2002-04-18'
        });

        const volunteerUserB = await upsertUser(connection, {
            name: 'Karim Nasser',
            email: 'volunteer.karim.test@civicconnect.local',
            role: 'Volunteer'
        });
        const volunteerB = await upsertVolunteer(connection, volunteerUserB, {
            phone: '+961 71 333 444',
            city: 'Jounieh',
            skills: 'Logistics, Photography, Social media',
            interests: 'Environment, Community',
            experiences: 'Campus club media lead, beach cleanup volunteer',
            dob: '2001-09-05'
        });

        const volunteerUserC = await upsertUser(connection, {
            name: 'Rana Saade',
            email: 'volunteer.rana.test@civicconnect.local',
            role: 'Volunteer'
        });
        const volunteerC = await upsertVolunteer(connection, volunteerUserC, {
            phone: '+961 76 555 666',
            city: 'Beirut',
            skills: 'First aid, Communication, Data entry',
            interests: 'Health, Elderly Care, Disability Support',
            experiences: 'Red Cross first aid workshop, elderly home visit program',
            dob: '2000-12-12'
        });

        const foodDrive = await upsertOpportunity(connection, ngoA, {
            title: 'TEST - Community Food Drive',
            field: 'Food Distribution',
            description: 'Pack and distribute weekly food parcels for families in need. Volunteers help sort supplies, welcome families, and record parcel counts.',
            startDate: '2026-05-04',
            endDate: '2026-05-04',
            scheduleDays: 'MON',
            startTime: '09:00',
            endTime: '13:00',
            hours: 4,
            capacity: 6,
            location: 'Hamra Community Hall'
        });

        await upsertOpportunity(connection, ngoA, {
            title: 'TEST - Youth Literacy Circle',
            field: 'Education',
            description: 'Support middle-school students with reading practice, homework structure, and confidence-building activities.',
            startDate: '2026-05-11',
            endDate: '2026-05-18',
            scheduleDays: 'MON,WED',
            startTime: '15:00',
            endTime: '17:00',
            hours: 8,
            capacity: 4,
            location: 'Ras Beirut Learning Center'
        });

        const cleanup = await upsertOpportunity(connection, ngoB, {
            title: 'TEST - Waterfront Cleanup Sprint',
            field: 'Environment',
            description: 'A fast-paced cleanup and sorting day near the waterfront, including recycling documentation and awareness photos.',
            startDate: '2026-04-10',
            endDate: '2026-04-10',
            scheduleDays: 'FRI',
            startTime: '08:00',
            endTime: '13:00',
            hours: 5,
            capacity: 10,
            location: 'Beirut Waterfront'
        });

        const health = await upsertOpportunity(connection, ngoB, {
            title: 'TEST - Health Awareness Booth',
            field: 'Health',
            description: 'Help operate a friendly public booth sharing basic prevention information and guiding visitors to partner clinics.',
            startDate: '2026-05-20',
            endDate: '2026-05-20',
            scheduleDays: 'WED',
            startTime: '10:00',
            endTime: '13:00',
            hours: 3,
            capacity: 5,
            location: 'Achrafieh Public Garden'
        });

        const appMayaCleanup = await upsertApplication(connection, {
            volunteerId: volunteerA,
            opportunityId: cleanup,
            status: 'accepted',
            confirmed: true,
            hours: 5
        });
        const appKarimCleanup = await upsertApplication(connection, {
            volunteerId: volunteerB,
            opportunityId: cleanup,
            status: 'accepted',
            confirmed: true,
            hours: 5
        });
        await upsertApplication(connection, {
            volunteerId: volunteerC,
            opportunityId: cleanup,
            status: 'rejected',
            confirmed: false,
            hours: 0
        });

        await upsertApplication(connection, {
            volunteerId: volunteerA,
            opportunityId: foodDrive,
            status: 'pending',
            confirmed: false,
            hours: 0
        });
        await upsertApplication(connection, {
            volunteerId: volunteerB,
            opportunityId: foodDrive,
            status: 'accepted',
            confirmed: false,
            hours: 0
        });
        await upsertApplication(connection, {
            volunteerId: volunteerC,
            opportunityId: health,
            status: 'pending',
            confirmed: false,
            hours: 0
        });

        await upsertOpportunityFeedback(connection, {
            applicationId: appMayaCleanup,
            volunteerId: volunteerA,
            opportunityId: cleanup,
            rating: 5,
            comment: 'The cleanup was organized, welcoming, and meaningful. The NGO gave clear tasks and made volunteers feel useful from the first minute.',
            impactStory: 'We filled dozens of bags and sorted recyclable items before noon.'
        });

        await upsertVolunteerFeedback(connection, {
            applicationId: appMayaCleanup,
            ngoId: ngoB,
            volunteerId: volunteerA,
            rating: 5,
            title: 'Dependable and warm team contributor',
            comment: 'Maya arrived early, helped orient new volunteers, and stayed focused during the sorting stage. She would be welcome again.',
            strengths: 'Punctuality, teamwork, communication'
        });

        await upsertVolunteerFeedback(connection, {
            applicationId: appKarimCleanup,
            ngoId: ngoB,
            volunteerId: volunteerB,
            rating: 4,
            title: 'Strong logistics support',
            comment: 'Karim handled supply movement smoothly and documented the cleanup with useful photos for our report.',
            strengths: 'Logistics, initiative, media support'
        });

        await connection.commit();

        console.log('Seed data added successfully.');
        console.log(`Password for all test accounts: ${PASSWORD}`);
        console.log('Admin account:');
        console.log('  admin.test@civicconnect.local');
        console.log('NGO accounts:');
        console.log('  ngo.cedar.test@civicconnect.local');
        console.log('  ngo.green.test@civicconnect.local');
        console.log('Volunteer accounts:');
        console.log('  volunteer.maya.test@civicconnect.local');
        console.log('  volunteer.karim.test@civicconnect.local');
        console.log('  volunteer.rana.test@civicconnect.local');
    } catch (err) {
        await connection.rollback();
        console.error('Seed failed:', err);
        process.exitCode = 1;
    } finally {
        connection.release();
        await db.end();
    }
}

main();
