USE civicconnect;

DROP PROCEDURE IF EXISTS add_column_if_missing;
DROP PROCEDURE IF EXISTS add_index_if_missing;

DELIMITER //

CREATE PROCEDURE add_column_if_missing(
  IN p_table_name VARCHAR(64),
  IN p_column_name VARCHAR(64),
  IN p_column_definition TEXT
)
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name
      AND COLUMN_NAME = p_column_name
  ) THEN
    SET @sql = CONCAT('ALTER TABLE `', p_table_name, '` ADD COLUMN `', p_column_name, '` ', p_column_definition);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END IF;
END//

CREATE PROCEDURE add_index_if_missing(
  IN p_table_name VARCHAR(64),
  IN p_index_name VARCHAR(64),
  IN p_index_definition TEXT
)
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name
      AND INDEX_NAME = p_index_name
  ) THEN
    SET @sql = CONCAT('CREATE INDEX `', p_index_name, '` ON `', p_table_name, '` ', p_index_definition);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END IF;
END//

DELIMITER ;

CALL add_column_if_missing('Applications', 'attendance_confirmed', 'ENUM(''NO'', ''YES'') DEFAULT ''NO'' AFTER `status`');
CALL add_column_if_missing('Applications', 'hours_completed', 'INT NOT NULL DEFAULT 0 AFTER `attendance_confirmed`');
CALL add_column_if_missing('Applications', 'attendance_confirmed_at', 'TIMESTAMP NULL AFTER `hours_completed`');
CALL add_column_if_missing('NGOs', 'rejection_reason', 'TEXT NULL AFTER `approval_status`');

CREATE TABLE IF NOT EXISTS AuditLogs (
    audit_id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(80) NOT NULL,
    target_id VARCHAR(80),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id)
        REFERENCES Users(user_id)
        ON DELETE SET NULL
);

CALL add_index_if_missing('Applications', 'idx_applications_attendance', '(`attendance_confirmed`)');
CALL add_index_if_missing('AuditLogs', 'idx_audit_created_at', '(`created_at`)');
CALL add_index_if_missing('AuditLogs', 'idx_audit_admin', '(`admin_id`)');
CALL add_index_if_missing('NGOs', 'idx_ngos_approval_status', '(`approval_status`)');

DROP PROCEDURE add_column_if_missing;
DROP PROCEDURE add_index_if_missing;
