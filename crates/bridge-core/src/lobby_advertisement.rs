//! Opt-in room advertisement translation, never inbound data or member metadata.
//! Schema: Protobufs 6c35e1ad6b5401e4f95cd0923e8145a23613516c (MMS).
//! Legacy framing: SteamKit 2049844fdf746420c9f31a9575d4b75c40a5d575 KeyValue.cs.
//!
//! Steam's MMS server mirrors lobby metadata in BOTH the legacy binary-KV blob
//! (field 8) and protobuf pair records (field 12) inside a single server->client
//! CMsgClientMMLobbyData (emsg 6612) broadcast. `metadata()` reconciles the two
//! encodings when they agree; genuine conflicts remain hard errors. Byte-level
//! rewriting stays strict: a dual-format message is never rewritten, because
//! patching one encoding would desynchronize the surviving mirror.
use crate::{bad, protocol as p};
use serde_json::{json, Value};
use std::{borrow::Cow, io, ops::Range};

const LIMIT: usize = 65536;
const ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdvertisePlatform {
    #[default]
    Preserve,
    Default,
}
impl AdvertisePlatform {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "preserve" => Ok(Self::Preserve),
            "default" => Ok(Self::Default),
            _ => Err(bad("advertise_platform_option")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::Default => "default",
        }
    }
}

fn fields(bytes: &[u8]) -> io::Result<Vec<p::Field<'_>>> {
    if bytes.len() > LIMIT {
        return Err(bad("advertisement_limit"));
    }
    let f = p::fields(bytes)?;
    if f.len() > 1024 {
        return Err(bad("advertisement_limit"));
    }
    Ok(f)
}
fn single<'a>(f: &[p::Field<'a>], n: u32, wire: u8) -> io::Result<Option<&'a [u8]>> {
    let mut found = f.iter().filter(|x| x.number == n);
    let Some(x) = found.next() else {
        return Ok(None);
    };
    if x.wire != wire || found.next().is_some() {
        return Err(bad("advertisement_field"));
    }
    Ok(Some(x.value))
}
fn number(f: &[p::Field<'_>], n: u32) -> io::Result<Option<u64>> {
    single(f, n, 0)?.map(|v| p::varint(v, &mut 0)).transpose()
}
fn fixed(f: &[p::Field<'_>], n: u32) -> io::Result<Option<u64>> {
    single(f, n, 1)?
    .map(|v| {
        v.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| bad("advertisement_fixed"))
    })
    .transpose()
}

struct Entry<'a> {
    key: &'a [u8],
    value: Option<&'a [u8]>,
    span: Option<Range<usize>>,
    pair_index: Option<usize>,
}
struct Metadata<'a> {
    source: &'static str,
    entries: Vec<Entry<'a>>,
    legacy: Option<&'a [u8]>,
    /// Number of protobuf pair fields mirroring the legacy KV blob
    /// (server->client lobby broadcasts carry both formats). None when the
    /// message is not dual-format.
    mirrored_pairs: Option<usize>,
}
/// One validated protobuf pair record (field 1 key, optional field 2 value),
/// remembering its position among the message's protobuf fields.
struct Pair<'a> {
    key: &'a [u8],
    value: Option<&'a [u8]>,
    index: usize,
}
fn cstring<'a>(data: &'a [u8], at: &mut usize) -> io::Result<&'a [u8]> {
    let start = *at;
    let size = data
    .get(start..)
    .ok_or_else(|| bad("kv_truncated"))?
    .iter()
    .position(|b| *b == 0)
    .ok_or_else(|| bad("kv_string"))?;
    if size > 4096 {
        return Err(bad("kv_string_limit"));
    }
    *at += size + 1;
    let value = &data[start..start + size];
    std::str::from_utf8(value).map_err(|_| bad("kv_utf8"))?;
    Ok(value)
}
// Validate all nested data, but only root children are lobby metadata. Never
// interpret a similarly named key in a nested arbitrary object as room metadata.
fn kv_children<'a>(
    data: &'a [u8],
    at: &mut usize,
    depth: usize,
    budget: &mut usize,
    entries: &mut Vec<Entry<'a>>,
) -> io::Result<()> {
    if depth > 8 {
        return Err(bad("kv_depth"));
    }
    loop {
        let kind = *data.get(*at).ok_or_else(|| bad("kv_truncated"))?;
        *at += 1;
        if kind == 8 || kind == 11 {
            return Ok(());
        }
        *budget += 1;
        if *budget > ENTRIES {
            return Err(bad("kv_entries"));
        }
        let key = cstring(data, at)?;
        let mut value = None;
        let mut span = None;
        match kind {
            0 => kv_children(data, at, depth + 1, budget, entries)?,
            1 => {
                let start = *at;
                value = Some(cstring(data, at)?);
                span = Some(start..*at - 1);
            }
            2 | 3 | 4 | 6 => *at += 4,
            7 | 10 => *at += 8,
            _ => return Err(bad("kv_unsupported_type")),
        }
        if *at > data.len() {
            return Err(bad("kv_truncated"));
        }
        if depth == 1 {
            entries.push(Entry {
                key,
                value,
                span,
                pair_index: None,
            });
        }
    }
}
// Shared pair-record validation for the protobuf_pairs source and for the
// mirror reconciliation path, so both branches enforce identical limits.
fn pair_records<'a>(pairs: &[(usize, &p::Field<'a>)]) -> io::Result<Vec<Pair<'a>>> {
    if pairs.len() > ENTRIES {
        return Err(bad("metadata_entries"));
    }
    let mut records = Vec::with_capacity(pairs.len());
    for &(index, pair) in pairs {
        if pair.wire != 2 {
            return Err(bad("metadata_pair_wire"));
        }
        let pf = fields(pair.value)?;
        let key = single(&pf, 1, 2)?.ok_or_else(|| bad("metadata_pair_name"))?;
        let value = single(&pf, 2, 2)?;
        if key.len() > 4096 || value.is_some_and(|v| v.len() > 4096) {
            return Err(bad("metadata_string_limit"));
        }
        std::str::from_utf8(key).map_err(|_| bad("metadata_utf8"))?;
        if let Some(v) = value {
            std::str::from_utf8(v).map_err(|_| bad("metadata_utf8"))?;
        }
        records.push(Pair { key, value, index });
    }
    Ok(records)
}
// Dual-format reconciliation: every pair record must correspond to a legacy
// KV entry with a matching key (ASCII case-insensitively, like the duplicate
// check) and an identical value. Keys are unique at this point (the duplicate
// check below would fail a message otherwise), so a linear find is sufficient.
// An omitted pair value denotes an empty string; non-string KV kinds have no
// value and match only an omitted pair value.
fn reconcile_mirror(entries: &[Entry<'_>], records: &[Pair<'_>]) -> io::Result<()> {
    if entries.len() != records.len() {
        return Err(bad("metadata_dual_format"));
    }
    for record in records {
        let Some(entry) = entries.iter().find(|e| e.key.eq_ignore_ascii_case(record.key)) else {
            return Err(bad("metadata_dual_format"));
        };
        match (entry.value, record.value) {
            (Some(v), Some(r)) if v == r => {}
            (Some(v), None) if v.is_empty() => {}
            (None, None) => {}
            _ => return Err(bad("metadata_dual_format")),
        }
    }
    Ok(())
}
fn metadata<'a>(f: &[p::Field<'a>], legacy_n: u32, pairs_n: u32) -> io::Result<Metadata<'a>> {
    let legacy = single(f, legacy_n, 2)?.filter(|b| !b.is_empty());
    let pairs: Vec<_> = f
    .iter()
    .enumerate()
    .filter(|(_, x)| x.number == pairs_n)
    .collect();
    let mut entries = Vec::new();
    let source;
    let mirrored_pairs;
    if let Some(data) = legacy {
        source = "legacy_binary_kv";
        if data.first() != Some(&0) {
            return Err(bad("kv_root"));
        }
        let mut at = 1;
        cstring(data, &mut at)?;
        kv_children(data, &mut at, 1, &mut 0, &mut entries)?;
        // SteamKit binary serialization closes the root and the outer stream.
        if !matches!(data.get(at), Some(8 | 11)) || at + 1 != data.len() {
            return Err(bad("kv_terminator"));
        }
        if pairs.is_empty() {
            mirrored_pairs = None;
        } else {
            // Steam's MMS mirrors the same metadata in both encodings inside a
            // single server->client lobby broadcast. Decode against the KV
            // blob; the mirror is accepted only when it agrees exactly.
            let records = pair_records(&pairs)?;
            reconcile_mirror(&entries, &records)?;
            mirrored_pairs = Some(records.len());
        }
    } else if !pairs.is_empty() {
        source = "protobuf_pairs";
        let records = pair_records(&pairs)?;
        mirrored_pairs = None;
        entries = records
        .into_iter()
        .map(|r| Entry {
            key: r.key,
            value: r.value,
            span: None,
            pair_index: Some(r.index),
        })
        .collect();
    } else {
        source = "absent";
        mirrored_pairs = None;
    }
    for (i, entry) in entries.iter().enumerate() {
        if entries[..i]
            .iter()
            .any(|prior| prior.key.eq_ignore_ascii_case(entry.key))
            {
                return Err(bad("metadata_duplicate"));
            }
    }
    Ok(Metadata {
        source,
       entries,
       legacy,
       mirrored_pairs,
    })
}
fn safe_metadata(meta: &Metadata<'_>) -> Value {
    let mut safe = serde_json::Map::new();
    for e in &meta.entries {
        let words: &[&str] = match e.key {
            b"game:platform" => &["ps3", "default", "pc"],
            b"game:mode" => &["coop", "sp", "mp", "coop_challenge", "coop_community"],
            b"game:state" => &["lobby", "game", "waiting", "ingame"],
            b"system:access" => &["public", "friends", "private"],
            b"system:lock" => {
                safe.insert(
                    "system:lock".into(),
                            json!(e
                            .value
                            .map(|v| if v.is_empty() { "empty" } else { "nonempty" })),
                );
                continue;
            }
            _ => continue,
        };
        let word = e
        .value
        .and_then(|v| words.iter().find(|w| v.eq_ignore_ascii_case(w.as_bytes())));
        safe.insert(std::str::from_utf8(e.key).unwrap().into(), json!(word));
    }
    json!({"source":meta.source,"entry_count":meta.entries.len(),"allowed":safe,
        "mirrored_protobuf_pairs":meta.mirrored_pairs})
}
fn decode(message: &[u8]) -> io::Result<Value> {
    let (id, _, body) = p::proto(message)?;
    let f = fields(body)?;
    let app = number(&f, 1)?;
    if app != Some(620) {
        return Ok(json!({"emsg":id,"status":"other_or_missing_app"}));
    }
    if id == 6602 || id == 6610 {
        let result = number(&f, 3)?;
        return Ok(json!({"emsg":id,"status":"decoded","app_id":620,
            "eresult":result.unwrap_or(2),"eresult_defaulted":result.is_none()}));
    }
    if id == 6619 || id == 6620 {
        return Ok(json!({"emsg":id,"status":"decoded","app_id":620}));
    }
    let (capacity, kind, flags, legacy, pairs) = match id {
        6601 => (2, 3, 4, 7, 11),
        6609 => (4, 5, 6, 7, 9),
        6612 => (4, 5, 6, 8, 12),
        _ => return Err(bad("advertisement_message")),
    };
    let member = id == 6609 && fixed(&f, 3)?.is_some_and(|v| v != 0);
    let meta = if member {
        json!({"source":"member_metadata_omitted"})
    } else {
        safe_metadata(&metadata(&f, legacy, pairs)?)
    };
    let kind = number(&f, kind)?;
    Ok(
        json!({"emsg":id,"status":"decoded","app_id":620,"member_update":member,
            "max_members":number(&f,capacity)?.filter(|v| *v <= 250),
              "num_members":if id == 6612 { number(&f,3)?.filter(|v| *v <= 250) } else { None },
              "lobby_type":kind.filter(|v| *v <= 4),
              "lobby_type_name":kind.and_then(|v| ["private","friends","public","invisible","private_unique"].get(v as usize)),
              "flags_raw":number(&f,flags)?.filter(|v| *v <= 65535),"metadata":meta}),
    )
}
pub fn summarize(message: &[u8]) -> Option<Value> {
    let id = p::id(message).ok()?;
    if ![6601, 6602, 6609, 6610, 6612, 6619, 6620].contains(&id) {
        return None;
    }
    Some(decode(message).unwrap_or_else(
        |_| json!({"emsg":id,"status":"unavailable","reason":"malformed_ambiguous_or_limit"}),
    ))
}

fn rewrite(message: &[u8]) -> io::Result<(Option<Vec<u8>>, &'static str, &'static str)> {
    let (id, header, body) = p::proto(message)?;
    let f = fields(body)?;
    if number(&f, 1)? != Some(620) {
        return Ok((None, "other_or_missing_app", "absent"));
    }
    // Validate all known singular request fields before changing any byte.
    let numeric: &[u32] = if id == 6601 {
        &[2, 3, 4, 5, 6]
    } else {
        &[4, 5, 6]
    };
    let blobs: &[u32] = if id == 6601 { &[7, 8, 9, 10] } else { &[7, 8] };
    for n in numeric {
        single(&f, *n, 0)?;
    }
    for n in blobs {
        single(&f, *n, 2)?;
    }
    if id == 6609 {
        if fixed(&f, 3)?.is_some_and(|v| v != 0) {
            return Ok((None, "member_update", "omitted"));
        }
        if fixed(&f, 2)?.is_none_or(|v| v == 0) {
            return Err(bad("missing_lobby"));
        }
    }
    let pairs = if id == 6601 { 11 } else { 9 };
    let meta = metadata(&f, 7, pairs)?;
    // Patching one encoding of a dual-format message would leave the mirror
    // contradicting it, so dual-format input is never rewritten.
    if meta.mirrored_pairs.is_some() {
        return Err(bad("metadata_dual_format"));
    }
    let Some(entry) = meta.entries.iter().find(|e| e.key == b"game:platform") else {
        return Ok((None, "no_platform", meta.source));
    };
    let Some(value) = entry.value else {
        return Err(bad("platform_not_string"));
    };
    if value == b"default" {
        return Ok((None, "already_default", meta.source));
    }
    if !value.eq_ignore_ascii_case(b"ps3") {
        return Ok((None, "other_platform", meta.source));
    }
    let mut out = Vec::new();
    for (i, field) in f.iter().enumerate() {
        if let Some(data) = meta.legacy.filter(|_| field.number == 7) {
            let span = entry.span.clone().ok_or_else(|| bad("platform_span"))?;
            let mut changed = Vec::new();
            changed.extend_from_slice(&data[..span.start]);
            changed.extend_from_slice(b"default");
            changed.extend_from_slice(&data[span.end..]);
            p::bin(7, &changed, &mut out);
        } else if entry.pair_index == Some(i) {
            let mut pair = Vec::new();
            for part in fields(field.value)? {
                if part.number == 2 {
                    p::bin(2, b"default", &mut pair);
                } else {
                    pair.extend_from_slice(part.raw);
                }
            }
            p::bin(pairs, &pair, &mut out);
        } else {
            out.extend_from_slice(field.raw);
        }
    }
    if out.len() > LIMIT {
        return Err(bad("advertisement_output_limit"));
    }
    Ok((Some(p::message(id, header, &out)), "rewritten", meta.source))
}

/// Call only for client -> Steam traffic. Default and unsupported input are exact
/// passthrough. Audit contains fixed categories, never unknown metadata or IDs.
pub fn adapt(message: &[u8], policy: AdvertisePlatform) -> (Cow<'_, [u8]>, Option<Value>) {
    let id = p::id(message).ok();
    if policy == AdvertisePlatform::Preserve || !matches!(id, Some(6601 | 6609)) {
        return (Cow::Borrowed(message), None);
    }
    let (changed, reason, source) =
    rewrite(message).unwrap_or((None, "malformed_ambiguous_or_limit", "unknown"));
    let audit = json!({"emsg":id,"policy":"default","changed":changed.is_some(),"reason":reason,"source":source,
        "before":summarize(message),"after":changed.as_ref().and_then(|b| summarize(b))});
    (
        changed.map(Cow::Owned).unwrap_or(Cow::Borrowed(message)),
     Some(audit),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rebuild a legacy binary-KV blob: root, empty root name, `01 key 00 value 00`
    // string children, then the root and stream closers.
    fn kv_blob(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = vec![0u8, 0u8];
        for (k, v) in pairs {
            out.push(1);
            out.extend_from_slice(k.as_bytes());
            out.push(0);
            out.extend_from_slice(v.as_bytes());
            out.push(0);
        }
        out.extend_from_slice(&[8u8, 8]);
        out
    }
    // Rebuild the mirrored protobuf pair records (message field 12).
    fn pair_records_bytes(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in pairs {
            let mut rec = Vec::new();
            p::bin(1, k.as_bytes(), &mut rec);
            p::bin(2, v.as_bytes(), &mut rec);
            p::bin(12, &rec, &mut out);
        }
        out
    }
    fn lobby_6612(kv: &[u8], mirror: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        p::vi(1, 620, &mut body);
        p::vi(3, 1, &mut body); // num_members
        p::vi(4, 2, &mut body); // max_members
        p::vi(5, 0, &mut body); // lobby_type: private
        p::vi(6, 3, &mut body); // flags
        p::bin(8, kv, &mut body);
        body.extend_from_slice(mirror);
        p::message(6612, &[], &body)
    }
    const META: &[(&str, &str)] = &[
        ("members:numMachines", "1"),
        ("members:numPlayers", "1"),
        ("members:numSlots", "2"),
        ("system:network", "LIVE"),
        ("system:access", "private"),
        ("game:mode", "coop"),
        ("game:map", "default"),
        ("game:mp_coop_start", "0"),
        ("game:sixense_features", "1"),
        ("game:state", "lobby"),
        ("game:dlcrequired", "0"),
        ("options:server", "official"),
    ];

    #[test]
    fn dual_format_broadcast_decodes_when_mirror_agrees() {
        let message = lobby_6612(&kv_blob(META), &pair_records_bytes(META));
        let summary = summarize(&message).expect("6612 is summarized");
        assert_eq!(summary["status"], "decoded");
        assert_eq!(summary["num_members"], 1);
        assert_eq!(summary["metadata"]["source"], "legacy_binary_kv");
        assert_eq!(summary["metadata"]["entry_count"], 12);
        assert_eq!(summary["metadata"]["mirrored_protobuf_pairs"], 12);
    }

    #[test]
    fn dual_format_rejected_when_mirror_conflicts() {
        let mut conflicted = Vec::from(META);
        conflicted[1].1 = "3"; // differs from the KV blob
        let message = lobby_6612(&kv_blob(META), &pair_records_bytes(&conflicted));
        let summary = summarize(&message).expect("6612 is summarized");
        assert_eq!(summary["status"], "unavailable");
        assert_eq!(summary["reason"], "malformed_ambiguous_or_limit");
    }

    #[test]
    fn kv_only_broadcast_still_decodes_without_mirror_field() {
        let message = lobby_6612(&kv_blob(META), &[]);
        let summary = summarize(&message).expect("6612 is summarized");
        assert_eq!(summary["status"], "decoded");
        assert!(summary["metadata"]["mirrored_protobuf_pairs"].is_null());
    }

    #[test]
    fn mirror_with_extra_pair_is_rejected() {
        let mut extra = Vec::from(pair_records_bytes(META));
        let mut rec = Vec::new();
        p::bin(1, b"rogue:key", &mut rec);
        p::bin(2, b"rogue", &mut rec);
        p::bin(12, &rec, &mut extra);
        let message = lobby_6612(&kv_blob(META), &extra);
        let summary = summarize(&message).expect("6612 is summarized");
        assert_eq!(summary["status"], "unavailable");
    }
}
