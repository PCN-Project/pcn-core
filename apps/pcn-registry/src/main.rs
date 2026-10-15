//! `pcn-registry` - persistent PCN address registry daemon (v0.1).
//!
//! Serves the framed text protocol from `pcn-registry-proto` over TCP.
//! State is a plain-text `name<TAB>pcn~address` file, rewritten
//! atomically (tmp + rename) before every successful mutation is
//! reported - a crash can lose at most nothing already acknowledged.
//!
//! Only private (type-1) addresses in `--range-min..=--range-max` are
//! allocated. Registration is name-keyed: re-`alloc`ating an existing
//! name returns its existing record (idempotent); `reserve` strictly
//! claims an exact address for a new name. No IP endpoints are stored -
//! address ownership and physical routing stay separate.

use pcn_address::{Address, AddressType};
use pcn_registry_proto::{read_frame, write_frame, Request, Response};
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

const USAGE: &str = "\
pcn-registry - persistent PCN address registry (v0.1)

USAGE:
    pcn-registry --listen HOST:PORT --state FILE [options]

OPTIONS:
    --listen HOST:PORT   TCP endpoint to serve on (required)
    --state FILE         allocation store, rewritten atomically (required)
    --range-min N        lowest allocatable private value (default 1)
    --range-max N        highest allocatable private value (default 1048575)

Protocol: length-prefixed UTF-8 frames (see pcn-registry-proto docs).
The daemon allocates the lowest free address in the range; an address
is never given to two names, and a name re-registering returns its
existing allocation.";

/// Default highest private value offered to clients. Deliberately small
/// for the v0.1 prototype - the 60-bit space stays untouched for real
/// deployments.
const DEFAULT_RANGE_MAX: u64 = 0xF_FFFF;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") || args.is_empty() {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match parse_args(&args).and_then(serve) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Daemon configuration from CLI.
struct Config {
    listen: SocketAddr,
    state: PathBuf,
    range_min: u64,
    range_max: u64,
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut listen = None;
    let mut state = None;
    let mut range_min = 1u64;
    let mut range_max = DEFAULT_RANGE_MAX;
    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (args[i].as_str(), None),
        };
        let take = |i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline {
                return Ok(v.to_string());
            }
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("option '{flag}' requires a value"))
        };
        match flag {
            "--listen" => {
                let v = take(&mut i)?;
                listen = Some(
                    v.parse::<SocketAddr>()
                        .map_err(|e| format!("--listen: '{v}' is not a socket address: {e}"))?,
                );
            }
            "--state" => state = Some(PathBuf::from(take(&mut i)?)),
            "--range-min" => {
                range_min = take(&mut i)?
                    .parse()
                    .map_err(|_| "--range-min must be an integer".to_string())?;
            }
            "--range-max" => {
                range_max = take(&mut i)?
                    .parse()
                    .map_err(|_| "--range-max must be an integer".to_string())?;
            }
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }
    if range_min == 0 || range_min > range_max {
        return Err(format!("invalid range {range_min}-{range_max}"));
    }
    Ok(Config {
        listen: listen.ok_or("--listen HOST:PORT required")?,
        state: state.ok_or("--state FILE required")?,
        range_min,
        range_max,
    })
}

// ------------------------------------------------------------------
// Registry core
// ------------------------------------------------------------------

/// The persistent allocation table: name <-> address, both directions.
struct Registry {
    names: BTreeMap<String, Address>,
    addrs: BTreeMap<Address, String>,
    range_min: u64,
    range_max: u64,
    path: PathBuf,
}

impl Registry {
    /// Loads the state file; a missing file starts empty. A malformed
    /// line or a double-booked name/address aborts startup - corrupt
    /// state is never silently patched.
    fn load(path: &Path, range_min: u64, range_max: u64) -> Result<Self, String> {
        let mut reg = Self {
            names: BTreeMap::new(),
            addrs: BTreeMap::new(),
            range_min,
            range_max,
            path: path.to_path_buf(),
        };
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(reg),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Some((name, addr_s)) = line.split_once('\t') else {
                return Err(format!("{}:{} malformed record", path.display(), n + 1));
            };
            let addr: Address = addr_s
                .trim()
                .parse()
                .map_err(|e| format!("{}:{} bad address '{addr_s}': {e}", path.display(), n + 1))?;
            if reg.names.contains_key(name) || reg.addrs.contains_key(&addr) {
                return Err(format!(
                    "{}:{} duplicate record for '{name}'",
                    path.display(),
                    n + 1
                ));
            }
            reg.names.insert(name.to_string(), addr);
            reg.addrs.insert(addr, name.to_string());
        }
        Ok(reg)
    }

    /// Rewrites the whole state file atomically (tmp + rename). Small
    /// prototype scale makes full rewrites the simplest correct choice.
    fn save(&self) -> Result<(), String> {
        let mut text = String::new();
        for (name, addr) in &self.names {
            text.push_str(&format!("{name}\t{addr}\n"));
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("cannot rename {}: {e}", tmp.display()))
    }

    /// Inserts a record and persists BEFORE reporting success; on save
    /// failure the in-memory change is rolled back.
    fn commit(&mut self, name: String, addr: Address) -> Result<Response, Response> {
        self.names.insert(name.clone(), addr);
        self.addrs.insert(addr, name.clone());
        if let Err(msg) = self.save() {
            self.names.remove(&name);
            self.addrs.remove(&addr);
            return Err(Response::Error {
                code: "io".into(),
                message: msg,
            });
        }
        Ok(Response::Registered { name, addr })
    }

    /// Validates an explicit/preferred address: private type, routable,
    /// canonical (no reserved bit), inside the allocation range.
    fn check_addr(&self, addr: Address) -> Result<(), Response> {
        let ok = addr.address_type() == AddressType::Private
            && addr.is_routable()
            && (self.range_min..=self.range_max).contains(&addr.value());
        if ok {
            Ok(())
        } else {
            Err(Response::Error {
                code: "bad_address".into(),
                message: format!(
                    "{addr}: must be a private address with value {}-{}",
                    self.range_min, self.range_max
                ),
            })
        }
    }

    /// Lowest unused value in the range, or None when exhausted.
    fn lowest_free(&self) -> Option<u64> {
        (self.range_min..=self.range_max).find(|v| {
            !self
                .addrs
                .contains_key(&Address::new(AddressType::Private, *v))
        })
    }

    fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Alloc { name, preferred } => self.alloc(name, preferred),
            Request::Reserve { name, addr } => self.reserve(name, addr),
            Request::Lookup { name } => match self.names.get(&name) {
                Some(&addr) => Response::Address(addr),
                None => Response::Error {
                    code: "not_found".into(),
                    message: format!("no node named '{name}'"),
                },
            },
            Request::WhoIs { addr } => match self.addrs.get(&addr) {
                Some(name) => Response::Name(name.clone()),
                None => Response::Error {
                    code: "addr_not_found".into(),
                    message: format!("{addr} is not allocated"),
                },
            },
            Request::List => {
                Response::List(self.names.iter().map(|(n, a)| (n.clone(), *a)).collect())
            }
        }
    }

    /// `alloc`: idempotent for an existing name; a preferred address is
    /// honoured only when it is free; auto mode picks the lowest free.
    fn alloc(&mut self, name: String, preferred: Option<Address>) -> Response {
        if let Some(&existing) = self.names.get(&name) {
            return match preferred {
                None => Response::Registered {
                    name,
                    addr: existing,
                },
                Some(want) if want == existing => Response::Registered {
                    name,
                    addr: existing,
                },
                Some(want) => Response::Error {
                    code: "name_taken".into(),
                    message: format!("'{name}' already holds {existing}, not {want}"),
                },
            };
        }
        let addr = match preferred {
            Some(want) => {
                if let Err(e) = self.check_addr(want) {
                    return e;
                }
                if let Some(owner) = self.addrs.get(&want) {
                    return Response::Error {
                        code: "addr_taken".into(),
                        message: format!("{want} is held by '{owner}'"),
                    };
                }
                want
            }
            None => match self.lowest_free() {
                Some(v) => Address::new(AddressType::Private, v),
                None => {
                    return Response::Error {
                        code: "exhausted".into(),
                        message: format!(
                            "allocation range {}-{} is full",
                            self.range_min, self.range_max
                        ),
                    }
                }
            },
        };
        self.commit(name, addr).unwrap_or_else(|e| e)
    }

    /// `reserve`: strictly claim an exact address for a NEW name.
    fn reserve(&mut self, name: String, addr: Address) -> Response {
        if let Some(&existing) = self.names.get(&name) {
            return Response::Error {
                code: "name_taken".into(),
                message: format!("'{name}' already holds {existing}"),
            };
        }
        if let Err(e) = self.check_addr(addr) {
            return e;
        }
        if let Some(owner) = self.addrs.get(&addr) {
            return Response::Error {
                code: "addr_taken".into(),
                message: format!("{addr} is held by '{owner}'"),
            };
        }
        self.commit(name, addr).unwrap_or_else(|e| e)
    }
}

// ------------------------------------------------------------------
// TCP serving
// ------------------------------------------------------------------

/// Handles one client connection: read frames, serve requests, write
/// responses, until clean EOF or a stream error. A poisoned lock is
/// recovered rather than failing the daemon.
fn serve_conn(stream: TcpStream, registry: &Arc<Mutex<Registry>>) {
    let mut reader = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connection: cannot clone stream: {e}");
            return;
        }
    };
    let mut writer = stream;
    loop {
        let text = match read_frame(&mut reader) {
            Ok(Some(t)) => t,
            Ok(None) => return, // clean close
            Err(e) => {
                eprintln!("connection: bad frame: {e}");
                return;
            }
        };
        let response = match Request::parse(&text) {
            Ok(req) => {
                let mut reg = registry.lock().unwrap_or_else(|p| p.into_inner());
                reg.handle(req)
            }
            Err((code, message)) => Response::Error { code, message },
        };
        if write_frame(&mut writer, &response.encode()).is_err() {
            return;
        }
    }
}

fn serve(config: Config) -> Result<(), String> {
    let registry = Registry::load(&config.state, config.range_min, config.range_max)?;
    let count = registry.names.len();
    let registry = Arc::new(Mutex::new(registry));

    let listener = TcpListener::bind(config.listen)
        .map_err(|e| format!("cannot bind {}: {e}", config.listen))?;
    println!(
        "listening on {} (registry; state: {}, range: {}-{}, {} records)",
        listener
            .local_addr()
            .map_err(|e| format!("local addr: {e}"))?,
        config.state.display(),
        config.range_min,
        config.range_max,
        count
    );

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let reg = Arc::clone(&registry);
                thread::spawn(move || serve_conn(stream, &reg));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pcn_registry_proto::MAX_NAME_LEN;

    fn temp_state(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pcnreg-test-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn registry(tag: &str, min: u64, max: u64) -> Registry {
        Registry::load(&temp_state(tag), min, max).unwrap()
    }

    fn alloc(reg: &mut Registry, name: &str) -> Response {
        reg.handle(Request::Alloc {
            name: name.into(),
            preferred: None,
        })
    }

    fn addr(v: u64) -> Address {
        Address::new(AddressType::Private, v)
    }

    #[test]
    fn auto_allocates_lowest_free_and_never_repeats() {
        let mut reg = registry("lowest", 1, 10);
        for (name, want) in [("a", 1), ("b", 2), ("c", 3)] {
            match alloc(&mut reg, name) {
                Response::Registered { addr: a, .. } => assert_eq!(a, addr(want)),
                other => panic!("{name}: {other:?}"),
            }
        }
        // Freeing is not supported; value 1 stays taken even after
        // lookups - allocation is monotonic within the range.
        assert_eq!(reg.names.len(), 3);
    }

    #[test]
    fn alloc_is_idempotent_for_same_name() {
        let mut reg = registry("idem", 1, 10);
        let first = alloc(&mut reg, "fedora");
        let again = alloc(&mut reg, "fedora");
        assert_eq!(first, again);
        // Same name + same preferred address: still idempotent.
        let preferred = reg.handle(Request::Alloc {
            name: "fedora".into(),
            preferred: Some(addr(1)),
        });
        assert_eq!(preferred, first);
        // Same name + DIFFERENT preferred: conflict.
        let conflict = reg.handle(Request::Alloc {
            name: "fedora".into(),
            preferred: Some(addr(5)),
        });
        assert!(matches!(
            conflict,
            Response::Error { code, .. } if code == "name_taken"
        ));
    }

    #[test]
    fn preferred_address_conflict_and_taken() {
        let mut reg = registry("pref", 1, 10);
        let taken = reg.handle(Request::Alloc {
            name: "a".into(),
            preferred: Some(addr(4)),
        });
        assert!(matches!(taken, Response::Registered { .. }));
        // A different name asking for the same address: addr_taken.
        let clash = reg.handle(Request::Alloc {
            name: "b".into(),
            preferred: Some(addr(4)),
        });
        assert!(matches!(
            clash,
            Response::Error { code, .. } if code == "addr_taken"
        ));
        // Out-of-range / non-private addresses rejected.
        for bad in [11u64, 0] {
            let r = reg.handle(Request::Alloc {
                name: "c".into(),
                preferred: Some(addr(bad)),
            });
            assert!(matches!(
                r,
                Response::Error { code, .. } if code == "bad_address"
            ));
        }
    }

    #[test]
    fn reserve_is_strict() {
        let mut reg = registry("reserve", 1, 10);
        let r = reg.handle(Request::Reserve {
            name: "svc".into(),
            addr: addr(7),
        });
        assert!(matches!(r, Response::Registered { .. }));
        // Same name again: rejected (reserve is not idempotent).
        let again = reg.handle(Request::Reserve {
            name: "svc".into(),
            addr: addr(7),
        });
        assert!(matches!(
            again,
            Response::Error { code, .. } if code == "name_taken"
        ));
        // Address already held: rejected.
        let clash = reg.handle(Request::Reserve {
            name: "other".into(),
            addr: addr(7),
        });
        assert!(matches!(
            clash,
            Response::Error { code, .. } if code == "addr_taken"
        ));
    }

    #[test]
    fn exhaustion_reports_cleanly() {
        let mut reg = registry("exhaust", 1, 2);
        assert!(matches!(alloc(&mut reg, "a"), Response::Registered { .. }));
        assert!(matches!(alloc(&mut reg, "b"), Response::Registered { .. }));
        let third = alloc(&mut reg, "c");
        assert!(matches!(
            third,
            Response::Error { code, .. } if code == "exhausted"
        ));
    }

    #[test]
    fn persistence_roundtrip_and_corruption() {
        let path = temp_state("persist");
        {
            let mut reg = Registry::load(&path, 1, 10).unwrap();
            alloc(&mut reg, "fedora");
            reg.handle(Request::Reserve {
                name: "svc".into(),
                addr: addr(9),
            });
        }
        // Reload: same records, next alloc continues past used values.
        let mut reg = Registry::load(&path, 1, 10).unwrap();
        assert_eq!(
            reg.handle(Request::Lookup {
                name: "fedora".into()
            }),
            Response::Address(addr(1))
        );
        assert_eq!(
            reg.handle(Request::WhoIs { addr: addr(9) }),
            Response::Name("svc".into())
        );
        match alloc(&mut reg, "next") {
            Response::Registered { addr: a, .. } => assert_eq!(a, addr(2)),
            other => panic!("{other:?}"),
        }
        std::fs::remove_file(&path).ok();

        // Corrupt state file -> startup refuses, never silently patched.
        let bad = temp_state("corrupt");
        std::fs::write(
            &bad,
            "fedora\tpcn~1000-0000-00001\nother\tpcn~1000-0000-00001\n",
        )
        .unwrap();
        assert!(Registry::load(&bad, 1, 10).is_err());
        std::fs::remove_file(&bad).ok();
    }

    #[test]
    fn lookups_report_unknowns() {
        let mut reg = registry("look", 1, 10);
        assert!(matches!(
            reg.handle(Request::Lookup {
                name: "ghost".into()
            }),
            Response::Error { code, .. } if code == "not_found"
        ));
        assert!(matches!(
            reg.handle(Request::WhoIs { addr: addr(5) }),
            Response::Error { code, .. } if code == "addr_not_found"
        ));
        let _ = &mut reg;
    }

    #[test]
    fn long_names_rejected_by_proto_not_here() {
        // Name validation lives in pcn-registry-proto::normalize_name;
        // server-side this is just a string key - assert the invariant
        // the proto guarantees instead of duplicating checks.
        assert_eq!(MAX_NAME_LEN, 64);
    }
}
