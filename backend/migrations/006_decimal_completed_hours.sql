USE civicconnect;

ALTER TABLE Applications
  MODIFY hours_completed DECIMAL(6,2) NOT NULL DEFAULT 0;
