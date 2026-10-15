# PCN Addressing - v0.1 (provisional)

**Status:** provisional. The 8-byte wire size and the field layout below
are fixed; allocation policy (who may assign which values) is *not*
defined in v0.1.

## 1. Three different names

PCN keeps three concepts strictly separate. Implementations must not treat
one as another:

| Concept | Type | Changes when the node moves? |
|---|---|---|
| **PCN-ID** | stable cryptographic node identity | no - it *is* the node |
| **PCN routing address (PCN-ADDR)** | 8-byte locator in packet headers | may change with attachment |
| **Transport endpoint** | e.g. IP address + UDP port | may change per link/session |

Consequences:

- An IP address and UDP port is a *transport endpoint*, owned entirely by
  the transport layer. It must never be used as, or embedded in, a PCN
  identity or routing address.
- A PCN routing address is a locator, not an identity. When the mapping
  "PCN-ID ↔ address" is defined (future `pcn-identity` work), address
  changes will not require a new identity.
- PCN-ID is future work. Nothing in v0.1 claims authenticated identity.

## 2. Binary layout

A PCN-ADDR address is a 64-bit value, big-endian on the wire:

```text
bit  63        61 60                              1 0
    +------------+---------------------------------+---+
    | type (3)   |         value (60)              | r |
    +------------+---------------------------------+---+
```

- **Bits `[63:61]` - type** (3 bits). Encodes the address category.
- **Bits `[60:1]` - value** (60 bits). The address itself; private and
  public addresses use the same 60-bit field and full range.
- **Bit `[0]` - reserved.** Always `0`. An address with this bit set is
  malformed and must be rejected.

### Address types

| Type bits | Meaning |
|---:|---|
| `0` | reserved - the all-zero value is the *unspecified* address; no other use is assigned |
| `1` | private / local - meaningful inside a *PCN domain* |
| `2` | public - allocated from the PCN Global space |
| `3`–`7` | reserved for future assignment |

Only types 1 and 2 are routable in v0.1. The unspecified address
(type 0, value 0) may be *represented* - e.g. "no address assigned yet"
- but must never appear in a packet's source or destination field. The
same applies to every other unassigned type value.

There is no link-local, multicast, or other extra address category in
v0.1, and no additional prefix inside the value field for local
addresses - the type field is the only marking.

## 3. Text representation

For configs and logs a PCN-ADDR address is written as the prefix `pcn~`
followed by 13 Base32 characters grouped `4-4-5` with hyphens:

```text
pcn~TXXX-XXXX-XXXXX
```

- `T` is the first Base32 character and encodes the 3-bit type field.
- The remaining 12 characters encode the 60-bit value, big-endian.
- Alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (Crockford-style,
  uppercase only; `I`, `L`, `O`, `U` are excluded).

Examples (illustrative, not allocated addresses):

```text
pcn~1K4M-2X9R-06D3P    private/local
pcn~2K4M-2X9R-06D3P    public
pcn~0000-0000-00000    unspecified
```

A parser must reject: a wrong prefix form (e.g. `PCN~`, `pcn`, `pcn~~`,
or `pcn~` placed inside the digits - the prefix is either absent or
exactly `pcn~`), a wrong length, a wrong `4-4-5` grouping, characters
outside the alphabet, and type characters `3`–`7` (reserved, not yet
supported). The reserved bit `[0]` cannot be expressed in text form; it
is validated only on the wire. The text form never appears in a packet -
the wire form is always 8 raw big-endian bytes.

## 4. Address scopes

- **Private/local addresses** (type 1) are meaningful only inside a *PCN
  domain*. The same value may be allocated independently in different
  domains, so resolving a local address always requires domain context
  (`pcn_address::ScopedAddress` pairs an `Address` with a `DomainId`).
- **Public addresses** (type 2) are allocated from the centrally
  administered PCN Global space by authorized operators.
- A node is not required to hold a public address; local-only operation
  inside a private domain is fully supported.

v0.1 deliberately does **not** define how domains are numbered, how the
60-bit value space is assigned, or how global allocation is delegated.
Keeping allocation out of the wire spec avoids baking policy into the
format.

## 5. Domains

A *domain* is the administrative scope of local addressing. Anyone may
create an isolated private domain; domains that want global reachability
register with PCN Global operators (see `docs/architecture/network-model.md`).

`DomainId` is a 64-bit identifier. In v0.1 it is chosen by the domain's
administrator; a collision-resistant allocation scheme is future work.
`DomainId::UNSPECIFIED` (0) means "no domain context".

Note the sizes coincide (address and domain are both 64-bit) but they are
different types - a `DomainId` is never an `Address` and vice versa.

## 6. Planned (not implemented)

- Assignment rules for the 60-bit value space inside a domain.
- PCN Global allocation and delegation policy.
- PCN-ID ↔ address binding and its cryptographic proof.
- Inter-domain and global routing addressing policy.
- Additional address types (the `3`–`7` code points are held in reserve).
