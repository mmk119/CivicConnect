USE civicconnect;

DELIMITER $$

CREATE PROCEDURE add_column_if_missing(
    IN p_table_name VARCHAR(64),
    IN p_column_name VARCHAR(64),
    IN column_definition TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = p_table_name
          AND COLUMN_NAME = p_column_name
    ) THEN
        SET @sql = CONCAT('ALTER TABLE `', p_table_name, '` ADD COLUMN `', p_column_name, '` ', column_definition);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

CREATE PROCEDURE add_index_if_missing(
    IN p_table_name VARCHAR(64),
    IN p_index_name VARCHAR(64),
    IN index_definition TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = p_table_name
          AND INDEX_NAME = p_index_name
    ) THEN
        SET @sql = CONCAT('ALTER TABLE `', p_table_name, '` ADD ', index_definition);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

CALL add_column_if_missing('Volunteers', 'available_days', 'VARCHAR(50) NULL AFTER `experiences`')$$
CALL add_column_if_missing('Volunteers', 'available_start_time', 'TIME NULL AFTER `available_days`')$$
CALL add_column_if_missing('Volunteers', 'available_end_time', 'TIME NULL AFTER `available_start_time`')$$
CALL add_column_if_missing('Volunteers', 'preferred_fields', 'TEXT NULL AFTER `available_end_time`')$$
CALL add_column_if_missing('Volunteers', 'preferred_cities', 'TEXT NULL AFTER `preferred_fields`')$$

CALL add_column_if_missing('Opportunities', 'application_questions', 'TEXT NULL AFTER `location`')$$

CALL add_column_if_missing('Applications', 'application_answers', 'TEXT NULL AFTER `status`')$$
CALL add_column_if_missing('Applications', 'certificate_id', 'VARCHAR(64) NULL AFTER `attendance_confirmed_at`')$$
CALL add_index_if_missing('Applications', 'uniq_applications_certificate_id', 'UNIQUE INDEX `uniq_applications_certificate_id` (`certificate_id`)')$$

CALL add_column_if_missing('OpportunityFeedback', 'review_status', 'ENUM(''new'', ''reviewed'') NOT NULL DEFAULT ''new'' AFTER `impact_story`')$$
CALL add_column_if_missing('OpportunityFeedback', 'reviewed_at', 'TIMESTAMP NULL AFTER `review_status`')$$
CALL add_column_if_missing('VolunteerFeedback', 'review_status', 'ENUM(''new'', ''reviewed'') NOT NULL DEFAULT ''new'' AFTER `strengths`')$$
CALL add_column_if_missing('VolunteerFeedback', 'reviewed_at', 'TIMESTAMP NULL AFTER `review_status`')$$

CREATE TABLE IF NOT EXISTS FeedbackReports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    feedback_type ENUM('opportunity', 'volunteer') NOT NULL,
    feedback_id INT NOT NULL,
    reporter_user_id INT NULL,
    reason VARCHAR(255) NOT NULL,
    details TEXT NULL,
    status ENUM('open', 'reviewed', 'dismissed') NOT NULL DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP NULL,
    INDEX idx_feedback_reports_target (feedback_type, feedback_id),
    INDEX idx_feedback_reports_status (status),
    CONSTRAINT fk_feedback_reports_user
        FOREIGN KEY (reporter_user_id) REFERENCES Users(user_id)
        ON DELETE SET NULL
)$$

DROP PROCEDURE add_column_if_missing$$
DROP PROCEDURE add_index_if_missing$$

DELIMITER ;
