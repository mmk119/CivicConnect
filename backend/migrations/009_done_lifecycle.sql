USE civicconnect;

ALTER TABLE Opportunities
  ADD COLUMN status ENUM('open', 'closed', 'in_progress', 'completed', 'archived') NOT NULL DEFAULT 'open' AFTER `ngo_id`;

ALTER TABLE Opportunities
  ADD COLUMN finalized_at DATETIME NULL AFTER `status`;

ALTER TABLE Applications
  ADD COLUMN completion_status ENUM('pending', 'attended', 'no_show') NOT NULL DEFAULT 'pending' AFTER `attendance_confirmed`;

ALTER TABLE Applications
  ADD COLUMN completed_at DATETIME NULL AFTER `completion_status`;

ALTER TABLE Applications
  MODIFY COLUMN status ENUM('pending', 'accepted', 'rejected', 'withdrawn') NOT NULL DEFAULT 'pending';

ALTER TABLE Opportunities ADD INDEX idx_opportunities_status (`status`);

ALTER TABLE Applications ADD INDEX idx_applications_completion (`opportunity_id`, `status`, `completion_status`);

UPDATE Applications
SET completion_status = 'attended',
    completed_at = COALESCE(attendance_confirmed_at, NOW())
WHERE attendance_confirmed = 'YES'
  AND completion_status = 'pending';

UPDATE Opportunities
SET status = 'completed',
    finalized_at = COALESCE(finalized_at, NOW())
WHERE finalized_at IS NOT NULL
  AND status <> 'archived';
