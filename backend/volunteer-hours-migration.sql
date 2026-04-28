USE civicconnect;

ALTER TABLE Applications
  ADD COLUMN attendance_confirmed ENUM('NO', 'YES') DEFAULT 'NO' AFTER status,
  ADD COLUMN hours_completed INT NOT NULL DEFAULT 0 AFTER attendance_confirmed,
  ADD COLUMN attendance_confirmed_at TIMESTAMP NULL AFTER hours_completed;

CREATE INDEX idx_applications_attendance ON Applications(attendance_confirmed);
