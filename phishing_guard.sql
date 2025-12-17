-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 17, 2025 at 08:50 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `phishing_guard`
--

-- --------------------------------------------------------

--
-- Table structure for table `bank_whitelist`
--

CREATE TABLE `bank_whitelist` (
  `id` int(11) NOT NULL,
  `bank_name` varchar(255) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `added_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `bank_whitelist`
--

INSERT INTO `bank_whitelist` (`id`, `bank_name`, `domain`, `added_at`) VALUES
(1, 'Maybank', 'maybank2u.com.my', '2025-12-15 08:45:23'),
(2, 'CIMB Bank', 'cimb.com.my', '2025-12-15 08:45:23'),
(3, 'Public Bank', 'pbebank.com', '2025-12-15 08:45:23'),
(4, 'RHB Bank', 'rhbgroup.com', '2025-12-15 08:45:23'),
(5, 'Hong Leong Bank', 'hlb.com.my', '2025-12-15 08:45:23'),
(6, 'AmBank', 'ambank.com.my', '2025-12-15 08:45:23'),
(7, 'Bank Islam Malaysia', 'bankislam.com.my', '2025-12-15 08:45:23'),
(8, 'Alliance Bank', 'alliancebank.com.my', '2025-12-15 08:45:23'),
(9, 'Standard Chartered Malaysia', 'sc.com', '2025-12-15 08:45:23'),
(10, 'HSBC Malaysia', 'hsbc.com.my', '2025-12-15 08:45:23'),
(11, 'OCBC Malaysia', 'ocbc.com.my', '2025-12-15 08:45:23'),
(12, 'United Overseas Bank', 'uob.com.my', '2025-12-15 08:45:23'),
(13, 'Bank Rakyat', 'bankrakyat.com.my', '2025-12-15 08:45:23'),
(14, 'Affin Bank', 'affinbank.com.my', '2025-12-15 08:45:23'),
(15, 'Bank Muamalat', 'muamalat.com.my', '2025-12-15 08:45:23');

-- --------------------------------------------------------

--
-- Table structure for table `checked_urls`
--

CREATE TABLE `checked_urls` (
  `id` int(11) NOT NULL,
  `url` varchar(2048) NOT NULL,
  `https_status` tinyint(1) NOT NULL,
  `domain_age` int(11) DEFAULT NULL,
  `external_api_result` varchar(64) DEFAULT 'unknown',
  `risk_score` int(11) NOT NULL,
  `final_status` enum('safe','phishing') NOT NULL,
  `checked_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `checked_urls`
--

INSERT INTO `checked_urls` (`id`, `url`, `https_status`, `domain_age`, `external_api_result`, `risk_score`, `final_status`, `checked_at`) VALUES
(5, 'http://malicious-bank.com', 0, NULL, 'clean', 30, 'safe', '2025-12-15 08:41:34'),
(7, 'http://malicious-bank.com', 0, NULL, 'clean', 30, 'safe', '2025-12-15 09:50:07'),
(8, 'http://malicious-bank.com', 0, NULL, 'clean', 30, 'safe', '2025-12-15 10:06:54'),
(16, 'http://bit.ly/maybank-login', 0, 6421, 'suspicious', 100, 'phishing', '2025-12-16 06:13:25'),
(17, 'http://malicious-bank.com', 0, NULL, 'clean', 65, 'phishing', '2025-12-16 06:13:53'),
(18, 'http://maybank2u.com.my', 0, 9338, 'clean', 30, 'safe', '2025-12-16 06:14:49'),
(19, 'http://www.aclaydance.com/ncpf.php', 0, NULL, 'clean', 65, 'phishing', '2025-12-16 06:15:53'),
(20, 'http://malicious-bank.tk', 0, NULL, 'suspicious', 100, 'phishing', '2025-12-16 06:22:31'),
(21, 'http://www.aclaydance.com/ncpf.php', 0, NULL, 'phishing_db_hit', 100, 'phishing', '2025-12-17 07:01:46'),
(22, 'http://muamalat.com.my', 1, 8122, 'clean', 35, 'safe', '2025-12-17 07:04:10'),
(25, 'https://www.muamalat.com.my', 1, 8122, 'clean', 80, 'phishing', '2025-12-17 07:47:07'),
(27, 'http://muamalat.com.my', 1, 8122, 'clean', 35, '', '2025-12-17 07:47:52');

-- --------------------------------------------------------

--
-- Table structure for table `phishing_urls`
--

CREATE TABLE `phishing_urls` (
  `id` int(11) NOT NULL,
  `url` varchar(2048) NOT NULL,
  `source` varchar(255) DEFAULT 'manual',
  `added_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `phishing_urls`
--

INSERT INTO `phishing_urls` (`id`, `url`, `source`, `added_at`) VALUES
(1, 'http://malicious-bank-login.example\r\n', 'manual', '2025-12-15 10:09:34'),
(3, 'http://bit.ly/maybank-login', 'auto_detected', '2025-12-16 06:13:25'),
(4, 'http://malicious-bank.com', 'auto_detected', '2025-12-16 06:13:53'),
(5, 'http://www.aclaydance.com/ncpf.php', 'auto_detected', '2025-12-16 06:15:53'),
(6, 'http://malicious-bank.tk', 'auto_detected', '2025-12-16 06:22:31'),
(9, 'https://www.muamalat.com.my', 'auto_detected', '2025-12-17 07:47:07');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `email`, `password_hash`, `created_at`) VALUES
(2, 'admin@gmail.com', 'scrypt:32768:8:1$u46uqMo196H9Ivy1$e3e2707dfd9a032423058ec11f120bd6289846fd3afa63281f78eededbf35e20f272f4e5858c2a29f299a0f37f862042840bf3830c39c30751fb6e8f20fbf45c', '2025-12-15 09:08:20');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `bank_whitelist`
--
ALTER TABLE `bank_whitelist`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `domain` (`domain`);

--
-- Indexes for table `checked_urls`
--
ALTER TABLE `checked_urls`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_url` (`url`(768)),
  ADD KEY `idx_checked_at` (`checked_at`);

--
-- Indexes for table `phishing_urls`
--
ALTER TABLE `phishing_urls`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `url` (`url`) USING HASH;

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `bank_whitelist`
--
ALTER TABLE `bank_whitelist`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `checked_urls`
--
ALTER TABLE `checked_urls`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

--
-- AUTO_INCREMENT for table `phishing_urls`
--
ALTER TABLE `phishing_urls`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
