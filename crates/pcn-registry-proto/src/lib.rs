//! PCN address-registry protocol v0.1 - framed request/response over TCP.
//!
//! Wire format: every message is one frame = `u32` big-endian byte
//! length followed by that many UTF-8 bytes of text. Frames are capped
//! at [`MAX_FRAME`] bytes; nothing about TCP's read granularity is
//! assumed (partial frames and coalesced frames both parse).
//!
//! Text payloads (tokens separated by single spaces):
//!
//! - `alloc <name>` - allocate the lowest free private address
//! - `alloc <name> <pcn-address>` - allocate a preferred address
//! - `reserve <name> <pcn-address>` - claim an exact address (strict:
//!   the name must not exist)
//! - `lookup <name>` - name -> address
//! - `whois <pcn-address>` - address -> name
//! - `list` - all records
//!
//! Responses:
//!
//! - `ok registered <name> <pcn-address>`
//! - `ok addr <pcn-address>`
//! - `ok name <name>`
//! - `ok list <n>` followed by `<n>` lines `<name> <pcn-address>`
//! - `err <code> <message>`
//!
//! Error codes: `bad_request`, `invalid_name`, `bad_address`,
//! `name_taken`, `addr_taken`, `not_found`, `addr_not_found`,
//! `exhausted`, `io`.

use pcn_address::Address;
use std::fmt;
use std::io::{self, Read, Write};

/// Maximum frame payload: generous for `list` on a small prototype,
/// hard-capped so a malformed length cannot cause a huge allocation.
pub const MAX_FRAME: usize = 8192;

/// Maximum node-name length in bytes.
pub const MAX_NAME_LEN: usize = 64;

// ------------------------------------------------------------------
// Framing
// ------------------------------------------------------------------

/// Writes one length-prefixed UTF-8 frame.
///
/// # Errors
/// `InvalidInput` when `text` exceeds [`MAX_FRAME`]; otherwise the
/// stream's own I/O errors.
pub fn write_frame(w: &mut impl Write, text: &str) -> io::Result<()> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds MAX_FRAME",
        ));
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes())?;
    w.write_all(bytes)
}

/// Reads one frame; `Ok(None)` on clean EOF before a length prefix.
/// Oversized or partial frames are errors, never silent truncation.
///
/// # Errors
/// `InvalidData` on oversize/invalid UTF-8, `UnexpectedEof` mid-frame,
/// plus the stream's own errors.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<String>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid frame length {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is not UTF-8"))
}

// ------------------------------------------------------------------
// Names
// ------------------------------------------------------------------

/// Why a node name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Empty after normalization.
    Empty,
    /// Longer than [`MAX_NAME_LEN`].
    TooLong,
    /// Characters outside `[a-z0-9._-]` or separator at the edges.
    BadChars,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty name"),
            Self::TooLong => write!(f, "name exceeds {MAX_NAME_LEN} bytes"),
            Self::BadChars => write!(
                f,
                "allowed: a-z 0-9 . _ -, first and last must be alphanumeric"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// Normalizes (lowercases) and validates a node name.
/// Allowed: `[a-z0-9._-]`, 1-64 bytes, first and last alphanumeric.
///
/// # Errors
/// [`NameError`] variants describe the concrete violation.
pub fn normalize_name(raw: &str) -> Result<String, NameError> {
    let name = raw.trim().to_lowercase();
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    let alnum = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let valid = name
        .chars()
        .all(|c| alnum(c) || matches!(c, '.' | '_' | '-'))
        && name.chars().next().is_some_and(alnum)
        && name.chars().next_back().is_some_and(alnum);
    if !valid {
        return Err(NameError::BadChars);
    }
    Ok(name)
}

// ------------------------------------------------------------------
// Requests
// ------------------------------------------------------------------

/// A client request, decoded from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Allocate (or return the existing allocation of) `name`; when
    /// `preferred` is given, take exactly that address if free.
    Alloc {
        /// Normalized node name.
        name: String,
        /// Optional exact address request.
        preferred: Option<Address>,
    },
    /// Strictly claim `addr` for a *new* `name` (no idempotent reuse).
    Reserve {
        /// Normalized node name.
        name: String,
        /// Exact address to claim.
        addr: Address,
    },
    /// name -> address lookup.
    Lookup {
        /// Normalized node name.
        name: String,
    },
    /// address -> name lookup.
    WhoIs {
        /// The address to resolve.
        addr: Address,
    },
    /// List every record.
    List,
}

impl Request {
    /// Encodes to the single-line text form.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            Self::Alloc { name, preferred } => match preferred {
                Some(a) => format!("alloc {name} {a}"),
                None => format!("alloc {name}"),
            },
            Self::Reserve { name, addr } => format!("reserve {name} {addr}"),
            Self::Lookup { name } => format!("lookup {name}"),
            Self::WhoIs { addr } => format!("whois {addr}"),
            Self::List => "list".into(),
        }
    }

    /// Decodes a frame payload; unknown verbs and wrong arity are
    /// `bad_request`, invalid names `invalid_name`, invalid addresses
    /// `bad_address`.
    ///
    /// # Errors
    /// `(code, message)` pair matching the on-wire `err` codes.
    pub fn parse(text: &str) -> Result<Self, (String, String)> {
        let bad = |msg: &str| ("bad_request".to_string(), msg.to_string());
        let parts: Vec<&str> = text.split_whitespace().collect();
        let Some(verb) = parts.first() else {
            return Err(bad("empty request"));
        };
        match *verb {
            "alloc" => match parts.len() {
                2 => Ok(Self::Alloc {
                    name: parse_name(parts.get(1))?,
                    preferred: None,
                }),
                3 => Ok(Self::Alloc {
                    name: parse_name(parts.get(1))?,
                    preferred: Some(parse_address(parts[2])?),
                }),
                _ => Err(bad("alloc takes <name> [addr]")),
            },
            "reserve" => match parts.len() {
                3 => Ok(Self::Reserve {
                    name: parse_name(parts.get(1))?,
                    addr: parse_address(parts[2])?,
                }),
                _ => Err(bad("reserve takes <name> <addr>")),
            },
            "lookup" => match parts.len() {
                2 => Ok(Self::Lookup {
                    name: parse_name(parts.get(1))?,
                }),
                _ => Err(bad("lookup takes <name>")),
            },
            "whois" => match parts.len() {
                2 => Ok(Self::WhoIs {
                    addr: parse_address(parts[1])?,
                }),
                _ => Err(bad("whois takes <addr>")),
            },
            "list" => match parts.len() {
                1 => Ok(Self::List),
                _ => Err(bad("list takes no arguments")),
            },
            _ => Err(bad("unknown request (alloc|reserve|lookup|whois|list)")),
        }
    }
}

fn parse_name(raw: Option<&&str>) -> Result<String, (String, String)> {
    normalize_name(raw.copied().unwrap_or("")).map_err(|e| ("invalid_name".into(), format!("{e}")))
}

fn parse_address(text: &str) -> Result<Address, (String, String)> {
    text.parse::<Address>()
        .map_err(|e| ("bad_address".into(), format!("'{text}': {e}")))
}

// ------------------------------------------------------------------
// Responses
// ------------------------------------------------------------------

/// A server response, decoded from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `ok registered <name> <addr>` - alloc/reserve outcome.
    Registered {
        /// Normalized node name.
        name: String,
        /// The allocated address.
        addr: Address,
    },
    /// `ok addr <addr>` - lookup result.
    Address(Address),
    /// `ok name <name>` - whois result.
    Name(String),
    /// `ok list <n>` + n lines - full table.
    List(Vec<(String, Address)>),
    /// `err <code> <message>`.
    Error {
        /// Machine-readable code (e.g. `name_taken`).
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

impl Response {
    /// Encodes to the wire text form.
    #[must_use]
    pub fn encode(&self) -> String {
        match self {
            Self::Registered { name, addr } => format!("ok registered {name} {addr}"),
            Self::Address(a) => format!("ok addr {a}"),
            Self::Name(n) => format!("ok name {n}"),
            Self::List(entries) => {
                let mut s = format!("ok list {}", entries.len());
                for (name, addr) in entries {
                    s.push_str(&format!("\n{name} {addr}"));
                }
                s
            }
            Self::Error { code, message } => format!("err {code} {message}"),
        }
    }

    /// Decodes a frame payload.
    ///
    /// # Errors
    /// `(code, message)` for malformed frames (reported as
    /// `bad_response`).
    pub fn parse(text: &str) -> Result<Self, (String, String)> {
        let bad = |msg: &str| ("bad_response".to_string(), msg.to_string());
        if let Some(rest) = text.strip_prefix("err ") {
            let (code, msg) = rest.split_once(' ').unwrap_or((rest, ""));
            return Ok(Self::Error {
                code: code.to_string(),
                message: msg.to_string(),
            });
        }
        let Some(rest) = text.strip_prefix("ok ") else {
            return Err(bad("response is neither ok nor err"));
        };
        // `ok list N` carries newline-separated entries - handle it on
        // the raw remainder before splitting on spaces.
        if let Some(tail) = rest.strip_prefix("list ") {
            let (count_s, body) = tail.split_once('\n').unwrap_or((tail, ""));
            let count: usize = count_s
                .trim()
                .parse()
                .map_err(|_| bad("list needs a count"))?;
            let mut entries = Vec::with_capacity(count.min(4096));
            for line in body.lines().filter(|l| !l.is_empty()) {
                let mut kv = line.split_whitespace();
                let (Some(n), Some(a)) = (kv.next(), kv.next()) else {
                    return Err(bad("list entry malformed"));
                };
                entries.push((
                    n.to_string(),
                    a.parse().map_err(|_| bad("list: invalid addr"))?,
                ));
            }
            if entries.len() != count {
                return Err(bad("list count mismatch"));
            }
            return Ok(Self::List(entries));
        }
        let mut it = rest.split(' ');
        match it.next().unwrap_or("") {
            "registered" => {
                let name = it.next().ok_or_else(|| bad("registered needs name"))?;
                let addr = it.next().ok_or_else(|| bad("registered needs addr"))?;
                Ok(Self::Registered {
                    name: name.to_string(),
                    addr: addr.parse().map_err(|_| bad("registered: invalid addr"))?,
                })
            }
            "addr" => {
                let addr = it.next().ok_or_else(|| bad("addr needs value"))?;
                Ok(Self::Address(
                    addr.parse().map_err(|_| bad("addr invalid"))?,
                ))
            }
            "name" => {
                let name = it.next().ok_or_else(|| bad("name needs value"))?;
                Ok(Self::Name(name.to_string()))
            }
            _ => Err(bad("unknown ok variant")),
        }
    }
}

/// Convenience: the full request round-trip helpers share one error
/// shape - protocol `(code, message)` pairs.
pub type ProtoError = (String, String);

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pcn_address::AddressType;

    fn addr(v: u64) -> Address {
        Address::new(AddressType::Private, v)
    }

    // --- framing ---------------------------------------------------

    #[test]
    fn frame_roundtrip_and_partial_reads() {
        let mut buf = Vec::new();
        write_frame(&mut buf, "alloc fedora").unwrap();
        write_frame(&mut buf, "ok registered fedora pcn~1000-0000-00001").unwrap();
        // One byte at a time - TCP-like fragmentation.
        let mut cursor = io::Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor).unwrap().as_deref(),
            Some("alloc fedora")
        );
        assert!(read_frame(&mut cursor)
            .unwrap()
            .unwrap()
            .starts_with("ok registered"));
        assert_eq!(read_frame(&mut cursor).unwrap(), None); // clean EOF
    }

    #[test]
    fn frame_rejects_oversized_and_empty() {
        // Advertised length over the cap: rejected before allocation.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        let mut cursor = io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());

        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        let mut cursor = io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());

        // A zero-copy check: writing an oversized frame errors.
        let big = "x".repeat(MAX_FRAME + 1);
        assert!(write_frame(&mut io::sink(), &big).is_err());
    }

    #[test]
    fn frame_rejects_truncated_body_and_non_utf8() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(b"abc"); // promises 10, sends 3
        assert!(read_frame(&mut io::Cursor::new(buf)).is_err());

        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xff]); // invalid UTF-8
        assert!(read_frame(&mut io::Cursor::new(buf)).is_err());
    }

    // --- names ------------------------------------------------------

    #[test]
    fn name_validation() {
        assert_eq!(normalize_name("Fedora-PC_1").unwrap(), "fedora-pc_1");
        assert_eq!(normalize_name("a.b-c_d").unwrap(), "a.b-c_d");
        assert_eq!(normalize_name(""), Err(NameError::Empty));
        assert_eq!(normalize_name("  "), Err(NameError::Empty));
        assert_eq!(
            normalize_name(&"x".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::TooLong)
        );
        for bad in ["-lead", "trail-", "a b", "a/b", "a\tb", "@home"] {
            assert_eq!(
                normalize_name(bad),
                Err(NameError::BadChars),
                "{bad:?} must be rejected"
            );
        }
    }

    // --- requests ----------------------------------------------------

    #[test]
    fn request_roundtrip_all_verbs() {
        let reqs = [
            Request::Alloc {
                name: "fedora".into(),
                preferred: None,
            },
            Request::Alloc {
                name: "fedora".into(),
                preferred: Some(addr(7)),
            },
            Request::Reserve {
                name: "svc".into(),
                addr: addr(9),
            },
            Request::Lookup {
                name: "fedora".into(),
            },
            Request::WhoIs { addr: addr(7) },
            Request::List,
        ];
        for r in reqs {
            assert_eq!(Request::parse(&r.encode()).unwrap(), r, "{r:?}");
        }
    }

    #[test]
    fn request_parse_rejects_malformed() {
        for (text, code) in [
            ("", "bad_request"),
            ("frobnicate", "bad_request"),
            ("alloc", "bad_request"), // wrong arity
            ("alloc a b c", "bad_request"),
            ("alloc -bad-name", "invalid_name"),
            ("lookup", "bad_request"), // wrong arity
            ("whois pcn~1", "bad_address"),
            ("list extra", "bad_request"),
        ] {
            let err = Request::parse(text).unwrap_err();
            assert_eq!(err.0, code, "{text:?}");
        }
    }

    // --- responses ----------------------------------------------------

    #[test]
    fn response_roundtrip_all_variants() {
        let rsps = [
            Response::Registered {
                name: "fedora".into(),
                addr: addr(1),
            },
            Response::Address(addr(5)),
            Response::Name("fedora".into()),
            Response::List(vec![("a".into(), addr(1)), ("b".into(), addr(2))]),
            Response::Error {
                code: "name_taken".into(),
                message: "fedora".into(),
            },
        ];
        for r in rsps {
            assert_eq!(Response::parse(&r.encode()).unwrap(), r, "{r:?}");
        }
    }

    #[test]
    fn response_parse_rejects_malformed() {
        for text in [
            "",
            "wat",
            "ok",
            "ok list 2\na pcn~1000-0000-00001",
            "ok addr pcn~X",
        ] {
            assert!(Response::parse(text).is_err(), "{text:?}");
        }
        assert_eq!(
            Response::parse("err name_taken fedora").unwrap(),
            Response::Error {
                code: "name_taken".into(),
                message: "fedora".into()
            }
        );
    }
}
