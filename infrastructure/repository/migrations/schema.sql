-- usuario_auth schema
-- Run this script once against your MySQL instance before starting the server.
-- Example: mysql -u root -p < infrastructure/repository/migrations/schema.sql

CREATE DATABASE IF NOT EXISTS usuario_auth
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE usuario_auth;

CREATE TABLE IF NOT EXISTS users (
    id           VARCHAR(36)  NOT NULL,
    username     VARCHAR(100) NOT NULL,
    email        VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role         VARCHAR(20)  NOT NULL DEFAULT 'user',
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    created_at   DATETIME     NOT NULL,
    updated_at   DATETIME     NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email    (email),
    UNIQUE KEY uq_users_username (username),
    INDEX       idx_users_role   (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
