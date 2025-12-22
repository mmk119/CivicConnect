-- Adjusted SQL Dump
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';
START TRANSACTION;
SET time_zone = '+00:00';

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

DROP TABLE IF EXISTS `ngo_representatives`;
CREATE TABLE IF NOT EXISTS `ngo_representatives` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `full_name` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ngo_name` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ngo_email` VARCHAR(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ngo_description` TEXT COLLATE utf8mb4_unicode_ci NOT NULL,
  `website` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `location` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ngo_logo` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_verified` TINYINT(1) DEFAULT 0,
  `verification_code` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `reset_token` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `reset_token_expiration` TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ngo_email` (`ngo_email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `ngo_representatives` 
(`id`, `full_name`, `ngo_name`, `ngo_email`, `password`, `ngo_description`, `website`, `location`, `ngo_logo`, `email_verified`, `verification_code`, `created_at`, `reset_token`, `reset_token_expiration`) VALUES
(1, 'Mohammad Kassem', 'NGO', 'mohammad15kassem@gmail.com', 
 '$2y$10$xtIf9fwdHcce.zlpbgy11OhflV5mnqIq8uUNo0/VBcJMySbjxTp/S', '', 
 'http://NGO.com', 'SADAS', NULL, 0, '883309', '2025-02-10 19:30:31', NULL, NULL);

DROP TABLE IF EXISTS `volunteers`;
CREATE TABLE IF NOT EXISTS `volunteers` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `full_name` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` VARCHAR(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `date_of_birth` DATE DEFAULT NULL,
  `location` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `skills` TEXT COLLATE utf8mb4_unicode_ci,
  `reason` TEXT COLLATE utf8mb4_unicode_ci,
  `profile_picture` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email_verified` TINYINT(1) DEFAULT 0,
  `verification_code` VARCHAR(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `reset_token` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `reset_token_expiration` TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `volunteers` 
(`id`, `full_name`, `email`, `password`, `date_of_birth`, `location`, `skills`, `reason`, `profile_picture`, `email_verified`, `verification_code`, `created_at`, `reset_token`, `reset_token_expiration`) VALUES
(1, 'Mohammad Kassem', 'mohammad15kassem@gmail.com', 
 '$2y$10$0JdCv3BKX90EECfntA8d3O1n/v/dGz6O83I7eGdIjV8seNmisbBBa', NULL, 
 'Beirut', 'sa', '', NULL, 0, '143769', '2025-02-10 19:22:31', NULL, NULL);

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
