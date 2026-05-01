USE civicconnect;

ALTER TABLE Opportunities
  MODIFY hours_required DECIMAL(6,2) NOT NULL DEFAULT 1;
