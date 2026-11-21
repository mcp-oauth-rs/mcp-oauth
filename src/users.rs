//! Sign-in: an allowlist of e-mail addresses and single-use enrolment
//! codes, kept on disk in `state_dir/oauth-users.json`.
//!
//! An administrator allows an address ([`Users::allow`]) and asks for an
//! enrolment code ([`Users::enrol_code`]), which is shown once and handed to
//! the user out of band. The user types the address and the code on the
//! sign-in page of `/oauth/authorize`; the code works once, for that address
//! only, within [`ENROL_CODE_TTL`]. [`Users::revoke`] cuts the user off at
//! once: every token issued to them stops working, refresh tokens included.
//!
//! Only SHA-256 digests of the codes are stored (codes carry 80 random bits,
//! bound to their address). The file is shared by the server and the admin
//! tool, which may be another process: every change happens under an
//! exclusive lock on `oauth-users.lock` (read, modify, write atomically), and
//! the server reloads the file whenever it changed on disk.
//!
//! Revocation works through a generation number per user: a token family
//! remembers the generation its user had when it was issued, and every
//! revocation increments it, so families issued before are dead for good,
//! also when the address is allowed again later.

use crate::oauth::{digest, unix_now, write_atomic};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

/// Lifetime of an enrolment code: 24 hours.
pub const ENROL_CODE_TTL: u64 = 24 * 3600;
const USERS_FILE: &str = "oauth-users.json";
const LOCK_FILE: &str = "oauth-users.lock";
const MAX_USERS: usize = 10_000;
/// Crockford base32: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 16 symbols of 5 bits: 80 random bits.
const CODE_LEN: usize = 16;

/// One user as stored on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct UserRec {
    email: String,
    /// Incremented by every revocation; token families carry the
    /// generation they were issued under.
    generation: u64,
    active: bool,
    added_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<u64>,
    /// SHA-256 hex of the live enrolment code (see [`code_digest`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_sign_in_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Default)]
struct UsersFile {
    users: Vec<UserRec>,
}

/// A user as [`Users::list`] shows it. Never carries a code.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct User {
    /// Normalised address (trimmed, lower case).
    pub email: String,
    /// `false` after [`Users::revoke`], until [`Users::allow`] again.
    pub active: bool,
    /// When the address was first allowed (Unix seconds).
    pub added_at: u64,
    pub revoked_at: Option<u64>,
    /// Expiry of the unused enrolment code, if one is live.
    pub code_expires_at: Option<u64>,
    /// Last successful sign-in with an enrolment code.
    pub last_sign_in_at: Option<u64>,
}

/// Why an enrolment code was refused (logged by the server; the sign-in page
/// shows one message for all of them).
#[derive(Debug, PartialEq)]
pub(crate) enum Refused {
    /// Not an address, or not on the allowlist.
    UnknownEmail,
    Revoked,
    /// No live code for this address (never issued, or already used).
    NoCode,
    Expired,
    WrongCode,
    /// The users file cannot be read or written: nothing was consumed.
    Io(String),
    /// [`Users::allow`] beyond the bound on the allowlist.
    Full,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::UnknownEmail => f.write_str("address not on the allowlist"),
            Refused::Revoked => f.write_str("address revoked"),
            Refused::NoCode => f.write_str("no live code for this address (unused code needed)"),
            Refused::Expired => f.write_str("code expired"),
            Refused::WrongCode => f.write_str("wrong code"),
            Refused::Io(e) => write!(f, "users file: {e}"),
            Refused::Full => write!(f, "allowlist full ({MAX_USERS} addresses)"),
        }
    }
}

/// Identity of the file on disk: an atomic rename changes it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

struct Cache {
    /// `None`: the file does not exist (no users).
    stamp: Option<Stamp>,
    users: BTreeMap<String, UserRec>,
}

struct UsersInner {
    dir: PathBuf,
    cache: Mutex<Cache>,
}

/// The allowlist and its enrolment codes in a state directory: the admin
/// API (allow, enrol, revoke, list) for a command-line tool, and the store
/// the server checks on every sign-in, bearer token and refresh. Cheap to
/// clone (shared state). Several handles, in one process or several, may
/// work on the same directory at once.
#[derive(Clone)]
pub struct Users(Arc<UsersInner>);

/// Trimmed, lower case; one `@` with something on both sides; no spaces,
/// controls or characters that have no place in a plain address.
pub fn normalize_email(email: &str) -> Result<String, String> {
    let e = email.trim().to_lowercase();
    let bad = |why: &str| Err(format!("not an e-mail address ({why}): {email:?}"));
    if e.is_empty() || e.len() > 254 {
        return bad("length");
    }
    if e.chars()
        .any(|c| c.is_whitespace() || c.is_control() || "<>()[]\\,;:\"".contains(c))
    {
        return bad("character");
    }
    match e.split_once('@') {
        Some((l, d)) if !l.is_empty() && !d.is_empty() && !d.contains('@') => Ok(e),
        _ => bad("needs one @ between a local part and a domain"),
    }
}

/// The code as typed, canonical: upper case, without separators (spaces,
/// dashes), with Crockford's look-alikes mapped (O -> 0, I and L -> 1).
fn canonical_code(code: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for c in code.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_LEN).then_some(out)
}

/// Digest of a code bound to its address: a code is worth nothing for any
/// other address.
fn code_digest(email: &str, canonical: &str) -> String {
    digest(&format!(
        "mcp-oauth-server enrolment code\0{email}\0{canonical}"
    ))
}

fn new_code() -> String {
    let mut b = [0u8; CODE_LEN];
    getrandom::fill(&mut b).expect("OS random generator");
    // 256 is a multiple of 32: every symbol is uniform.
    let s: String = b
        .iter()
        .map(|x| ALPHABET[(x & 31) as usize] as char)
        .collect();
    // XXXX-XXXX-XXXX-XXXX
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

fn stamp(path: &Path) -> Result<Option<Stamp>, String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some(Stamp {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn read_users(path: &Path) -> Result<BTreeMap<String, UserRec>, String> {
    let f: UsersFile = match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => UsersFile::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    Ok(f.users.into_iter().map(|u| (u.email.clone(), u)).collect())
}

impl Users {
    /// The users of `state_dir` (created mode 700 if missing). Fails on an
    /// unreadable or corrupt `oauth-users.json`.
    pub fn open(state_dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = state_dir.into();
        if !dir.is_dir() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let path = dir.join(USERS_FILE);
        let st = stamp(&path)?;
        let users = read_users(&path)?;
        Ok(Self(Arc::new(UsersInner {
            dir,
            cache: Mutex::new(Cache { stamp: st, users }),
        })))
    }

    fn path(&self) -> PathBuf {
        self.0.dir.join(USERS_FILE)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        // The cache is replaced whole; a panic cannot leave it half-updated.
        self.0.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` on the users read fresh from disk, under the exclusive file
    /// lock, and write them back if `f` says they changed.
    fn update<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, UserRec>) -> Result<(T, bool), Refused>,
    ) -> Result<T, Refused> {
        use std::os::unix::fs::OpenOptionsExt;
        let io = |e: String| Refused::Io(e);
        let lock_path = self.0.dir.join(LOCK_FILE);
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| io(format!("{}: {e}", lock_path.display())))?;
        lock.lock()
            .map_err(|e| io(format!("lock {}: {e}", lock_path.display())))?;
        let path = self.path();
        let mut users = read_users(&path).map_err(io)?;
        let (out, changed) = f(&mut users)?;
        if changed {
            let mut v: Vec<UserRec> = users.values().cloned().collect();
            v.sort_by(|a, b| a.email.cmp(&b.email));
            let data = serde_json::to_vec(&UsersFile { users: v }).expect("serialize users");
            write_atomic(&self.0.dir, USERS_FILE, &data)
                .map_err(|e| io(format!("{}: {e}", path.display())))?;
        }
        let st = stamp(&path).map_err(io)?;
        *self.cache() = Cache { stamp: st, users };
        Ok(out)
        // `lock` is released when dropped (closing the file).
    }

    /// Put `email` on the allowlist, or allow it again after a revocation
    /// (tokens issued before the revocation stay dead). Returns `false` if
    /// it was already active.
    pub fn allow(&self, email: &str) -> Result<bool, String> {
        self.allow_at(email, unix_now())
    }

    pub(crate) fn allow_at(&self, email: &str, now: u64) -> Result<bool, String> {
        let email = normalize_email(email)?;
        self.update(|m| {
            let full = m.len() >= MAX_USERS;
            match m.get_mut(&email) {
                Some(u) if u.active => Ok((false, false)),
                Some(u) => {
                    u.active = true;
                    u.revoked_at = None;
                    Ok((true, true))
                }
                None if full => Err(Refused::Full),
                None => {
                    m.insert(
                        email.clone(),
                        UserRec {
                            email: email.clone(),
                            generation: 0,
                            active: true,
                            added_at: now,
                            revoked_at: None,
                            code_sha256: None,
                            code_expires_at: None,
                            last_sign_in_at: None,
                        },
                    );
                    Ok((true, true))
                }
            }
        })
        .map_err(|e| e.to_string())
    }

    /// A new single-use enrolment code for an allowed `email`, valid
    /// [`ENROL_CODE_TTL`] (24 h), formatted `XXXX-XXXX-XXXX-XXXX` (Crockford
    /// base32, 80 random bits; case, dashes and spaces do not matter when
    /// typed). It replaces any earlier unused code of that address. Only its
    /// digest is stored: show it once and hand it over.
    pub fn enrol_code(&self, email: &str) -> Result<String, String> {
        self.enrol_code_at(email, unix_now())
    }

    pub(crate) fn enrol_code_at(&self, email: &str, now: u64) -> Result<String, String> {
        let email = normalize_email(email)?;
        let code = new_code();
        let canon = canonical_code(&code).expect("generated code is canonical");
        self.update(|m| match m.get_mut(&email) {
            Some(u) if u.active => {
                u.code_sha256 = Some(code_digest(&email, &canon));
                u.code_expires_at = Some(now + ENROL_CODE_TTL);
                Ok(((), true))
            }
            Some(_) => Err(Refused::Revoked),
            None => Err(Refused::UnknownEmail),
        })
        .map_err(|e| match e {
            Refused::Io(e) => e,
            e => format!("{email}: {e}; allow it first"),
        })?;
        Ok(code)
    }

    /// Cut `email` off: it leaves the allowlist (kept as revoked), its
    /// unused code is dropped, and every access and refresh token issued to
    /// it stops working at once, for good. Returns `false` if it was not
    /// active.
    pub fn revoke(&self, email: &str) -> Result<bool, String> {
        self.revoke_at(email, unix_now())
    }

    pub(crate) fn revoke_at(&self, email: &str, now: u64) -> Result<bool, String> {
        let email = normalize_email(email)?;
        self.update(|m| match m.get_mut(&email) {
            Some(u) if u.active => {
                u.active = false;
                u.generation += 1;
                u.revoked_at = Some(now);
                u.code_sha256 = None;
                u.code_expires_at = None;
                Ok((true, true))
            }
            _ => Ok((false, false)),
        })
        .map_err(|e| e.to_string())
    }

    /// Every known address, active and revoked, sorted.
    pub fn list(&self) -> Result<Vec<User>, String> {
        let now = unix_now();
        self.update(|m| {
            let v = m
                .values()
                .map(|u| User {
                    email: u.email.clone(),
                    active: u.active,
                    added_at: u.added_at,
                    revoked_at: u.revoked_at,
                    code_expires_at: u
                        .code_sha256
                        .as_ref()
                        .and(u.code_expires_at)
                        .filter(|e| *e > now),
                    last_sign_in_at: u.last_sign_in_at,
                })
                .collect();
            Ok((v, false))
        })
        .map_err(|e| e.to_string())
    }

    /// Check and consume an enrolment code: on success the code is gone
    /// (also for every other process) and the user's address and current
    /// generation are returned.
    pub(crate) fn redeem(
        &self,
        email: &str,
        code: &str,
        now: u64,
    ) -> Result<(String, u64), Refused> {
        let Ok(email) = normalize_email(email) else {
            return Err(Refused::UnknownEmail);
        };
        // A malformed code is checked against an impossible digest, so the
        // outcome does not depend on the form of the code.
        let given = canonical_code(code)
            .map(|c| code_digest(&email, &c))
            .unwrap_or_default();
        self.update(|m| {
            let Some(u) = m.get_mut(&email) else {
                return Err(Refused::UnknownEmail);
            };
            if !u.active {
                return Err(Refused::Revoked);
            }
            let (Some(want), Some(exp)) = (u.code_sha256.as_deref(), u.code_expires_at) else {
                return Err(Refused::NoCode);
            };
            let same =
                want.len() == given.len() && bool::from(want.as_bytes().ct_eq(given.as_bytes()));
            if !same {
                return Err(Refused::WrongCode);
            }
            if exp <= now {
                return Err(Refused::Expired);
            }
            u.code_sha256 = None;
            u.code_expires_at = None;
            u.last_sign_in_at = Some(now);
            Ok(((u.email.clone(), u.generation), true))
        })
    }

    /// The generation of `email` (normalised) if it is active, read fresh
    /// from disk.
    pub(crate) fn active_generation(&self, email: &str) -> Result<Option<u64>, String> {
        self.update(|m| {
            let g = m.get(email).filter(|u| u.active).map(|u| u.generation);
            Ok((g, false))
        })
        .map_err(|e| e.to_string())
    }

    /// Whether `email` is active with this generation (its tokens are
    /// honoured). Reloads the file if it changed on disk; an unreadable file
    /// honours nobody.
    pub(crate) fn current(&self, email: &str, generation: u64) -> bool {
        let path = self.path();
        let mut c = self.cache();
        match stamp(&path) {
            Ok(s) if s == c.stamp => {}
            Ok(s) => match read_users(&path) {
                Ok(users) => *c = Cache { stamp: s, users },
                Err(e) => {
                    eprintln!("oauth: users file unreadable, refusing user tokens: {e}");
                    return false;
                }
            },
            Err(e) => {
                eprintln!("oauth: users file unreadable, refusing user tokens: {e}");
                return false;
            }
        }
        c.users
            .get(email)
            .is_some_and(|u| u.active && u.generation == generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::tests::tmp_dir;

    #[test]
    fn email_normalisation() {
        assert_eq!(
            normalize_email("  Ada@Example.ORG ").unwrap(),
            "ada@example.org"
        );
        for bad in [
            "",
            "ada",
            "@x",
            "ada@",
            "a b@x",
            "a@b@c",
            "<a@b>",
            "a,b@c",
            "a@b\nc",
            "a\u{0}b@c",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?}");
        }
        assert!(normalize_email(&format!("{}@x", "a".repeat(260))).is_err());
    }

    #[test]
    fn code_format_and_canonical_form() {
        let c = new_code();
        assert_eq!(c.len(), 19, "{c}");
        assert_eq!(c.matches('-').count(), 3);
        let canon = canonical_code(&c).unwrap();
        assert_eq!(canon.len(), CODE_LEN);
        assert_eq!(canonical_code(&c.to_lowercase()), Some(canon.clone()));
        assert_eq!(canonical_code(&c.replace('-', " ")), Some(canon.clone()));
        assert_eq!(
            canonical_code("oooo-iiii-llll-0000").as_deref(),
            Some("0000111111110000")
        );
        assert_eq!(canonical_code("short"), None);
        assert_eq!(
            canonical_code("UUUU-UUUU-UUUU-UUUU"),
            None,
            "U is not Crockford"
        );
        assert_eq!(canonical_code("ÀAAA-AAAA-AAAA-AAAA"), None);
        assert_ne!(new_code(), new_code());
        // A digest is bound to its address.
        assert_ne!(code_digest("a@x", &canon), code_digest("b@x", &canon));
    }

    #[test]
    fn admin_api_and_redeem() {
        let dir = tmp_dir("users");
        let u = Users::open(&dir).unwrap();
        let t = 1_000_000;
        assert!(u.list().unwrap().is_empty());
        assert!(u.enrol_code("ada@example.org").is_err(), "not allowed yet");
        assert!(u.allow_at("Ada@Example.org", t).unwrap());
        assert!(!u.allow("ada@example.org").unwrap(), "already active");
        let code = u.enrol_code_at("ADA@example.org", t).unwrap();
        let l = u.list().unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].email, "ada@example.org");
        assert!(l[0].active);
        assert_eq!(l[0].added_at, t);
        // The code itself is never stored.
        let raw = std::fs::read_to_string(dir.join(USERS_FILE)).unwrap();
        assert!(!raw.contains(&code) && !raw.contains(&canonical_code(&code).unwrap()));
        assert_eq!(
            u.redeem("ada@example.org", "0000-0000-0000-0000", t + 1),
            Err(Refused::WrongCode)
        );
        assert_eq!(
            u.redeem("ada@example.org", "nonsense", t + 1),
            Err(Refused::WrongCode)
        );
        assert_eq!(
            u.redeem("bob@example.org", &code, t + 1),
            Err(Refused::UnknownEmail)
        );
        let (email, generation) = u
            .redeem(" ADA@example.org", &code.to_lowercase(), t + 1)
            .unwrap();
        assert_eq!((email.as_str(), generation), ("ada@example.org", 0));
        assert_eq!(
            u.redeem("ada@example.org", &code, t + 2),
            Err(Refused::NoCode),
            "single use"
        );
        assert!(u.current("ada@example.org", 0));
        assert_eq!(u.list().unwrap()[0].last_sign_in_at, Some(t + 1));
        // Expiry.
        let code = u.enrol_code_at("ada@example.org", t).unwrap();
        assert_eq!(
            u.redeem("ada@example.org", &code, t + ENROL_CODE_TTL),
            Err(Refused::Expired)
        );
        assert!(
            u.redeem("ada@example.org", &code, t + ENROL_CODE_TTL - 1)
                .is_ok()
        );
        // A new code replaces the previous one.
        let old = u.enrol_code_at("ada@example.org", t).unwrap();
        let new = u.enrol_code_at("ada@example.org", t).unwrap();
        assert_eq!(
            u.redeem("ada@example.org", &old, t + 1),
            Err(Refused::WrongCode)
        );
        // Revocation drops the code and bumps the generation.
        assert!(u.revoke_at("ada@example.org", t + 5).unwrap());
        assert!(!u.revoke("ada@example.org").unwrap());
        assert!(!u.revoke("nobody@example.org").unwrap());
        assert_eq!(
            u.redeem("ada@example.org", &new, t + 6),
            Err(Refused::Revoked)
        );
        assert!(!u.current("ada@example.org", 0));
        let l = u.list().unwrap();
        assert_eq!(
            (l[0].active, l[0].revoked_at, l[0].code_expires_at),
            (false, Some(t + 5), None)
        );
        assert!(u.enrol_code("ada@example.org").is_err(), "revoked");
        // Allowed again: a new generation, the old tokens stay dead.
        assert!(u.allow("ada@example.org").unwrap());
        assert!(!u.current("ada@example.org", 0) && u.current("ada@example.org", 1));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The admin tool is another process: the server's handle sees its
    /// changes without a restart, and both write under one lock.
    #[test]
    fn two_handles_share_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("users2");
        let server = Users::open(&dir).unwrap();
        let admin = Users::open(&dir).unwrap();
        admin.allow("ada@example.org").unwrap();
        let code = admin.enrol_code("ada@example.org").unwrap();
        let now = unix_now();
        assert_eq!(server.redeem("ada@example.org", &code, now).unwrap().1, 0);
        assert!(server.current("ada@example.org", 0));
        admin.revoke("ada@example.org").unwrap();
        assert!(!server.current("ada@example.org", 0), "seen at once");
        for f in [USERS_FILE, LOCK_FILE] {
            let m = std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{f}");
        }
        // Concurrent admin changes are not lost.
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let d = dir.clone();
                std::thread::spawn(move || {
                    Users::open(&d)
                        .unwrap()
                        .allow(&format!("u{i}@example.org"))
                        .unwrap()
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().unwrap());
        }
        assert_eq!(server.list().unwrap().len(), 17);
        std::fs::write(dir.join(USERS_FILE), b"{corrupt").unwrap();
        assert!(
            !server.current("u1@example.org", 0),
            "corrupt file honours nobody"
        );
        assert!(Users::open(&dir).is_err(), "corrupt file is loud");
        let _ = std::fs::remove_dir_all(dir);
    }
}
