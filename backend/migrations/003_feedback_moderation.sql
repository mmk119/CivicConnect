USE civicconnect;

CREATE TABLE IF NOT EXISTS OpportunityFeedback (
    opportunity_feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    volunteer_id INT NOT NULL,
    opportunity_id INT NOT NULL,
    rating TINYINT NOT NULL,
    comment TEXT NOT NULL,
    impact_story TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_opportunity_feedback_application (application_id),
    INDEX idx_opportunity_feedback_opportunity (opportunity_id),
    INDEX idx_opportunity_feedback_volunteer (volunteer_id),

    CONSTRAINT chk_opportunity_feedback_rating CHECK (rating BETWEEN 1 AND 5),
    FOREIGN KEY (application_id)
        REFERENCES Applications(application_id)
        ON DELETE CASCADE,
    FOREIGN KEY (volunteer_id)
        REFERENCES Volunteers(volunteer_id)
        ON DELETE CASCADE,
    FOREIGN KEY (opportunity_id)
        REFERENCES Opportunities(opportunity_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS VolunteerFeedback (
    volunteer_feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    application_id INT NOT NULL,
    ngo_id INT NOT NULL,
    volunteer_id INT NOT NULL,
    rating TINYINT NOT NULL,
    endorsement_title VARCHAR(120) NOT NULL,
    comment TEXT NOT NULL,
    strengths TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_volunteer_feedback_application (application_id),
    INDEX idx_volunteer_feedback_volunteer (volunteer_id),
    INDEX idx_volunteer_feedback_ngo (ngo_id),

    CONSTRAINT chk_volunteer_feedback_rating CHECK (rating BETWEEN 1 AND 5),
    FOREIGN KEY (application_id)
        REFERENCES Applications(application_id)
        ON DELETE CASCADE,
    FOREIGN KEY (ngo_id)
        REFERENCES NGOs(ngo_id)
        ON DELETE CASCADE,
    FOREIGN KEY (volunteer_id)
        REFERENCES Volunteers(volunteer_id)
        ON DELETE CASCADE
);
