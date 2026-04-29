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

CALL add_column_if_missing('Opportunities', 'capacity', 'INT NULL AFTER `hours_required`');

CREATE TABLE IF NOT EXISTS SavedOpportunities (
    saved_id INT AUTO_INCREMENT PRIMARY KEY,
    volunteer_id INT NOT NULL,
    opportunity_id INT NOT NULL,
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_saved_opportunity (volunteer_id, opportunity_id),

    FOREIGN KEY (volunteer_id)
        REFERENCES Volunteers(volunteer_id)
        ON DELETE CASCADE,

    FOREIGN KEY (opportunity_id)
        REFERENCES Opportunities(opportunity_id)
        ON DELETE CASCADE
);

CALL add_index_if_missing('Opportunities', 'idx_opportunities_capacity', '(`capacity`)');
CALL add_index_if_missing('SavedOpportunities', 'idx_saved_volunteer', '(`volunteer_id`)');
CALL add_index_if_missing('SavedOpportunities', 'idx_saved_opportunity', '(`opportunity_id`)');

DROP PROCEDURE add_column_if_missing;
DROP PROCEDURE add_index_if_missing;
