//! Per-API request readers and response builders (ADR-0037). The worker reads
//! only what policy needs from a request: the topics (with the byte span of
//! each, so a request can be cut down to the allowed ones without
//! re-encoding what it doesn't understand), the group, and a few flags. It
//! builds the answer for what it refuses, and rewrites the three responses
//! that change: `Metadata` and `FindCoordinator` (broker addresses),
//! `OffsetFetch` (filtered), and `ApiVersions` (the worker's own).
//!
//! Versions are the non-flexible ones in [`super::wire::api::SUPPORTED`].

use std::collections::BTreeMap;

use super::wire::{Malformed, Reader, Writer, api, error};

/// One topic (or one topic-shaped element) of a request array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicSpan {
    pub name: String,
    /// Byte range of the element in the request body.
    pub start: usize,
    pub end: usize,
    /// The partitions the element names, for the answer to a refusal.
    pub partitions: Vec<i32>,
}

/// The array of topics in a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicArray {
    /// Where the `i32` count is.
    pub count_at: usize,
    /// The first byte after the last element.
    pub array_end: usize,
    pub spans: Vec<TopicSpan>,
}

impl TopicArray {
    /// The body with only the elements `keep` selects.
    #[must_use]
    pub fn cut(&self, body: &[u8], keep: &[bool]) -> Vec<u8> {
        let kept: Vec<&TopicSpan> = self
            .spans
            .iter()
            .zip(keep)
            .filter_map(|(s, k)| k.then_some(s))
            .collect();
        let mut out = Vec::with_capacity(body.len());
        out.extend_from_slice(&body[..self.count_at]);
        out.extend_from_slice(&i32::try_from(kept.len()).unwrap_or(0).to_be_bytes());
        for span in kept {
            out.extend_from_slice(&body[span.start..span.end]);
        }
        out.extend_from_slice(&body[self.array_end..]);
        out
    }
}

/// What a request asks for, as far as policy cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Produce {
        acks: i16,
        transactional: bool,
        topics: TopicArray,
    },
    Fetch {
        topics: TopicArray,
    },
    ListOffsets {
        topics: TopicArray,
    },
    /// `names` is `None` for "all topics".
    Metadata {
        names: Option<Vec<String>>,
    },
    OffsetCommit {
        group: String,
        topics: TopicArray,
    },
    /// `topics` is `None` for "every topic the group has offsets for".
    OffsetFetch {
        group: String,
        topics: Option<TopicArray>,
    },
    FindCoordinator {
        key: String,
        key_type: i8,
    },
    /// `JoinGroup`, `Heartbeat`, `LeaveGroup`, `SyncGroup`.
    Group {
        group: String,
    },
    CreateTopics {
        topics: TopicArray,
    },
    DeleteTopics {
        topics: TopicArray,
    },
    InitProducerId {
        transactional: bool,
    },
    SaslHandshake,
    SaslAuthenticate,
    ApiVersions,
}

/// Read the part of a request body that policy needs.
///
/// # Errors
/// If the body is cut short or an array length doesn't fit.
#[allow(clippy::too_many_lines)] // one flat table, clearer than split
pub fn parse_request(key: i16, version: i16, body: &[u8]) -> Result<Parsed, Malformed> {
    let mut r = Reader::new(body);
    Ok(match key {
        api::PRODUCE => {
            let transactional = r.nullable_string()?.is_some();
            let acks = r.i16()?;
            r.i32()?;
            let topics = topic_array(&mut r, |r| {
                let index = r.i32()?;
                r.skip_nullable_bytes()?;
                Ok(index)
            })?
            .ok_or(Malformed)?;
            Parsed::Produce {
                acks,
                transactional,
                topics,
            }
        }
        api::FETCH => {
            r.skip(16)?; // replica_id, max_wait_ms, min_bytes, max_bytes
            r.i8()?; // isolation_level
            if version >= 7 {
                r.skip(8)?; // session_id, session_epoch
            }
            let topics = topic_array(&mut r, |r| {
                let index = r.i32()?;
                if version >= 9 {
                    r.i32()?; // current_leader_epoch
                }
                r.i64()?; // fetch_offset
                if version >= 5 {
                    r.i64()?; // log_start_offset
                }
                r.i32()?; // partition_max_bytes
                Ok(index)
            })?
            .ok_or(Malformed)?;
            Parsed::Fetch { topics }
        }
        api::LIST_OFFSETS => {
            r.i32()?; // replica_id
            if version >= 2 {
                r.i8()?; // isolation_level
            }
            let topics = topic_array(&mut r, |r| {
                let index = r.i32()?;
                if version >= 4 {
                    r.i32()?; // current_leader_epoch
                }
                r.i64()?; // timestamp
                Ok(index)
            })?
            .ok_or(Malformed)?;
            Parsed::ListOffsets { topics }
        }
        api::METADATA => Parsed::Metadata {
            names: r.array(Reader::string)?,
        },
        api::OFFSET_COMMIT => {
            let group = r.string()?;
            r.i32()?; // generation_id
            r.string()?; // member_id
            if version >= 7 {
                r.nullable_string()?; // group_instance_id
            }
            if version <= 4 {
                r.i64()?; // retention_time_ms
            }
            let topics = topic_array(&mut r, |r| {
                let index = r.i32()?;
                r.i64()?; // committed_offset
                if version >= 6 {
                    r.i32()?; // committed_leader_epoch
                }
                r.nullable_string()?; // committed_metadata
                Ok(index)
            })?
            .ok_or(Malformed)?;
            Parsed::OffsetCommit { group, topics }
        }
        api::OFFSET_FETCH => {
            let group = r.string()?;
            let topics = topic_array(&mut r, |r| r.i32())?;
            Parsed::OffsetFetch { group, topics }
        }
        api::FIND_COORDINATOR => {
            let key = r.string()?;
            let key_type = if version >= 1 { r.i8()? } else { 0 };
            Parsed::FindCoordinator { key, key_type }
        }
        api::JOIN_GROUP | api::HEARTBEAT | api::LEAVE_GROUP | api::SYNC_GROUP => {
            Parsed::Group { group: r.string()? }
        }
        api::CREATE_TOPICS => {
            let start = r.pos();
            let count_at = start;
            let n = r.array_len()?.ok_or(Malformed)?;
            let mut spans = Vec::with_capacity(n.min(256));
            for _ in 0..n {
                let s = r.pos();
                let name = r.string()?;
                r.i32()?; // num_partitions
                r.i16()?; // replication_factor
                r.skip_array(|r| {
                    r.i32()?;
                    r.skip_array(|r| r.skip(4))
                })?;
                r.skip_array(|r| {
                    r.string()?;
                    r.nullable_string()?;
                    Ok(())
                })?;
                spans.push(TopicSpan {
                    name,
                    start: s,
                    end: r.pos(),
                    partitions: Vec::new(),
                });
            }
            Parsed::CreateTopics {
                topics: TopicArray {
                    count_at,
                    array_end: r.pos(),
                    spans,
                },
            }
        }
        api::DELETE_TOPICS => {
            let count_at = r.pos();
            let n = r.array_len()?.ok_or(Malformed)?;
            let mut spans = Vec::with_capacity(n.min(256));
            for _ in 0..n {
                let start = r.pos();
                let name = r.string()?;
                spans.push(TopicSpan {
                    name,
                    start,
                    end: r.pos(),
                    partitions: Vec::new(),
                });
            }
            Parsed::DeleteTopics {
                topics: TopicArray {
                    count_at,
                    array_end: r.pos(),
                    spans,
                },
            }
        }
        api::INIT_PRODUCER_ID => Parsed::InitProducerId {
            transactional: r.nullable_string()?.is_some(),
        },
        api::SASL_HANDSHAKE => Parsed::SaslHandshake,
        api::SASL_AUTHENTICATE => Parsed::SaslAuthenticate,
        api::API_VERSIONS => Parsed::ApiVersions,
        _ => return Err(Malformed),
    })
}

/// An array of `[name, partitions…]` elements. `None` for a null array.
fn topic_array(
    r: &mut Reader<'_>,
    mut partition: impl FnMut(&mut Reader<'_>) -> Result<i32, Malformed>,
) -> Result<Option<TopicArray>, Malformed> {
    let count_at = r.pos();
    let Some(n) = r.array_len()? else {
        return Ok(None);
    };
    let mut spans = Vec::with_capacity(n.min(256));
    for _ in 0..n {
        let start = r.pos();
        let name = r.string()?;
        let partitions = r.array(&mut partition)?.unwrap_or_default();
        spans.push(TopicSpan {
            name,
            start,
            end: r.pos(),
            partitions,
        });
    }
    Ok(Some(TopicArray {
        count_at,
        array_end: r.pos(),
        spans,
    }))
}

/// A `Metadata` request with only the `names` it should ask for, and no
/// automatic topic creation unless `allow_auto_create`.
///
/// # Errors
/// If the body is malformed.
pub fn rewrite_metadata_request(
    version: i16,
    body: &[u8],
    names: Option<&[String]>,
    allow_auto_create: bool,
) -> Result<Vec<u8>, Malformed> {
    let mut r = Reader::new(body);
    r.array(Reader::string)?;
    let mut rest = body[r.pos()..].to_vec();
    if version >= 4 && !rest.is_empty() && !allow_auto_create {
        rest[0] = 0;
    }
    let mut w = Writer::new();
    match names {
        None => w = w.i32(-1),
        Some(names) => {
            w = w.i32(i32::try_from(names.len()).map_err(|_| Malformed)?);
            for n in names {
                w = w.string(n);
            }
        }
    }
    Ok(w.raw(&rest).finish())
}

// ---- answers to what is refused -------------------------------------------

/// The partitions of a refused topic: index and error.
fn partition_errors(partitions: &[i32], per: impl Fn(Writer, i32) -> Writer) -> Writer {
    let mut w = Writer::new().i32(i32::try_from(partitions.len()).unwrap_or(0));
    for p in partitions {
        w = per(w, *p);
    }
    w
}

/// Add an entry for each refused topic to a response whose topic array is
/// where the API puts it, with `error` for every partition.
///
/// # Errors
/// If the response is too short to hold the array the API promises.
pub fn append_refused(
    key: i16,
    version: i16,
    resp: &[u8],
    refused: &[&TopicSpan],
    error: i16,
) -> Result<Vec<u8>, Malformed> {
    if refused.is_empty() {
        return Ok(resp.to_vec());
    }
    let v = version;
    // Where the count of the array is, and where new elements go.
    let (count_at, insert_at) = match key {
        api::PRODUCE => (0, resp.len().checked_sub(4).ok_or(Malformed)?),
        api::FETCH => {
            let at = if v >= 7 { 4 + 2 + 4 } else { 4 };
            (at, resp.len())
        }
        api::LIST_OFFSETS => (if v >= 2 { 4 } else { 0 }, resp.len()),
        api::OFFSET_COMMIT => (if v >= 3 { 4 } else { 0 }, resp.len()),
        api::OFFSET_FETCH => {
            let tail = if v >= 2 { 2 } else { 0 };
            (
                if v >= 3 { 4 } else { 0 },
                resp.len().checked_sub(tail).ok_or(Malformed)?,
            )
        }
        api::CREATE_TOPICS => (if v >= 2 { 4 } else { 0 }, resp.len()),
        api::DELETE_TOPICS => (if v >= 1 { 4 } else { 0 }, resp.len()),
        _ => return Err(Malformed),
    };
    if count_at + 4 > insert_at || insert_at > resp.len() {
        return Err(Malformed);
    }
    let mut count = [0u8; 4];
    count.copy_from_slice(&resp[count_at..count_at + 4]);
    let count = i32::from_be_bytes(count);
    if count < 0 {
        return Err(Malformed);
    }
    let mut added = Vec::new();
    for t in refused {
        let w = Writer::new().string(&t.name);
        let w = match key {
            api::PRODUCE => w.raw(
                &partition_errors(&t.partitions, |w, p| {
                    let w = w.i32(p).i16(error).i64(-1).i64(-1); // base_offset, log_append_time
                    let w = if v >= 5 { w.i64(-1) } else { w }; // log_start_offset
                    if v >= 8 {
                        w.i32(0).nullable_string(None) // record_errors, error_message
                    } else {
                        w
                    }
                })
                .finish(),
            ),
            api::FETCH => w.raw(
                &partition_errors(&t.partitions, |w, p| {
                    // high_watermark, last_stable_offset, log_start_offset (v5+)
                    let w = w.i32(p).i16(error).i64(-1).i64(-1);
                    let w = if v >= 5 { w.i64(-1) } else { w };
                    let w = w.i32(-1); // aborted_transactions: null
                    let w = if v >= 11 { w.i32(-1) } else { w }; // preferred_read_replica
                    w.i32(-1) // records: null
                })
                .finish(),
            ),
            api::LIST_OFFSETS => w.raw(
                &partition_errors(&t.partitions, |w, p| {
                    let w = w.i32(p).i16(error).i64(-1).i64(-1);
                    if v >= 4 { w.i32(-1) } else { w }
                })
                .finish(),
            ),
            api::OFFSET_COMMIT => {
                w.raw(&partition_errors(&t.partitions, |w, p| w.i32(p).i16(error)).finish())
            }
            api::OFFSET_FETCH => w.raw(
                &partition_errors(&t.partitions, |w, p| {
                    let w = w.i32(p).i64(-1);
                    let w = if v >= 5 { w.i32(-1) } else { w };
                    w.nullable_string(None).i16(error)
                })
                .finish(),
            ),
            api::CREATE_TOPICS => {
                let w = w.i16(error);
                if v >= 1 { w.nullable_string(None) } else { w }
            }
            api::DELETE_TOPICS => w.i16(error),
            _ => return Err(Malformed),
        };
        added.extend_from_slice(&w.finish());
    }
    let total = count
        .checked_add(i32::try_from(refused.len()).map_err(|_| Malformed)?)
        .ok_or(Malformed)?;
    let mut out = Vec::with_capacity(resp.len() + added.len());
    out.extend_from_slice(&resp[..count_at]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&resp[count_at + 4..insert_at]);
    out.extend_from_slice(&added);
    out.extend_from_slice(&resp[insert_at..]);
    Ok(out)
}

/// The whole response to a request that is refused outright (every topic
/// refused, or a group the role doesn't reach).
///
/// # Errors
/// If `key` is not an API with a refusal answer.
#[allow(clippy::too_many_lines)]
pub fn refusal_response(
    key: i16,
    version: i16,
    parsed: &Parsed,
    error: i16,
) -> Result<Vec<u8>, Malformed> {
    let v = version;
    Ok(match key {
        api::JOIN_GROUP => {
            let w = if v >= 2 {
                Writer::new().i32(0)
            } else {
                Writer::new()
            };
            w.i16(error)
                .i32(-1)
                .string("")
                .string("")
                .string("")
                .i32(0)
                .finish()
        }
        api::HEARTBEAT => {
            let w = if v >= 1 {
                Writer::new().i32(0)
            } else {
                Writer::new()
            };
            w.i16(error).finish()
        }
        api::LEAVE_GROUP => {
            let w = if v >= 1 {
                Writer::new().i32(0)
            } else {
                Writer::new()
            };
            let w = w.i16(error);
            if v >= 3 {
                w.i32(0).finish()
            } else {
                w.finish()
            }
        }
        api::SYNC_GROUP => {
            let w = if v >= 1 {
                Writer::new().i32(0)
            } else {
                Writer::new()
            };
            w.i16(error).i32(0).finish()
        }
        api::FIND_COORDINATOR => {
            if v == 0 {
                Writer::new().i16(error).i32(-1).string("").i32(-1).finish()
            } else {
                Writer::new()
                    .i32(0)
                    .i16(error)
                    .nullable_string(None)
                    .i32(-1)
                    .string("")
                    .i32(-1)
                    .finish()
            }
        }
        api::INIT_PRODUCER_ID => Writer::new().i32(0).i16(error).i64(-1).i16(-1).finish(),
        api::OFFSET_FETCH => {
            // Offsets of a group the role doesn't reach: nothing to show, and
            // the error at the end where the version has one.
            let w = if v >= 3 {
                Writer::new().i32(0)
            } else {
                Writer::new()
            };
            let w = w.i32(0);
            if v >= 2 {
                w.i16(error).finish()
            } else {
                w.finish()
            }
        }
        api::PRODUCE
        | api::FETCH
        | api::LIST_OFFSETS
        | api::OFFSET_COMMIT
        | api::CREATE_TOPICS
        | api::DELETE_TOPICS => {
            // An empty response with every refused topic appended.
            let topics = match parsed {
                Parsed::Produce { topics, .. }
                | Parsed::Fetch { topics }
                | Parsed::ListOffsets { topics }
                | Parsed::OffsetCommit { topics, .. }
                | Parsed::CreateTopics { topics }
                | Parsed::DeleteTopics { topics } => topics,
                _ => return Err(Malformed),
            };
            let base = empty_topic_response(key, v);
            let refused: Vec<&TopicSpan> = topics.spans.iter().collect();
            append_refused(key, v, &base, &refused, error)?
        }
        _ => return Err(Malformed),
    })
}

/// A response with no topics, in the shape of `key` at `version`.
fn empty_topic_response(key: i16, v: i16) -> Vec<u8> {
    let w = Writer::new();
    match key {
        api::PRODUCE => w.i32(0).i32(0).finish(), // responses, throttle_time_ms
        api::FETCH => {
            let w = w.i32(0); // throttle_time_ms
            let w = if v >= 7 { w.i16(0).i32(0) } else { w }; // error_code, session_id
            w.i32(0).finish()
        }
        api::LIST_OFFSETS => {
            let w = if v >= 2 { w.i32(0) } else { w };
            w.i32(0).finish()
        }
        api::OFFSET_COMMIT => {
            let w = if v >= 3 { w.i32(0) } else { w };
            w.i32(0).finish()
        }
        api::CREATE_TOPICS => {
            let w = if v >= 2 { w.i32(0) } else { w };
            w.i32(0).finish()
        }
        api::DELETE_TOPICS => {
            let w = if v >= 1 { w.i32(0) } else { w };
            w.i32(0).finish()
        }
        _ => w.finish(),
    }
}

// ---- Metadata ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broker {
    pub node_id: i32,
    pub host: String,
    pub port: i32,
    pub rack: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPartition {
    pub error: i16,
    pub index: i32,
    pub leader: i32,
    pub leader_epoch: i32,
    pub replicas: Vec<i32>,
    pub isr: Vec<i32>,
    pub offline: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataTopic {
    pub error: i16,
    pub name: String,
    pub internal: bool,
    pub partitions: Vec<MetadataPartition>,
    pub authorized_operations: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataResponse {
    pub throttle_ms: i32,
    pub brokers: Vec<Broker>,
    pub cluster_id: Option<String>,
    pub controller_id: i32,
    pub topics: Vec<MetadataTopic>,
    pub cluster_authorized_operations: i32,
}

fn ints(r: &mut Reader<'_>) -> Result<Vec<i32>, Malformed> {
    Ok(r.array(Reader::i32)?.unwrap_or_default())
}

fn put_ints(mut w: Writer, v: &[i32]) -> Writer {
    w = w.i32(i32::try_from(v.len()).unwrap_or(0));
    for i in v {
        w = w.i32(*i);
    }
    w
}

impl MetadataResponse {
    /// # Errors
    /// If the body doesn't have the shape of a `Metadata` response at `version`.
    pub fn decode(version: i16, body: &[u8]) -> Result<Self, Malformed> {
        let v = version;
        let mut r = Reader::new(body);
        let throttle_ms = if v >= 3 { r.i32()? } else { 0 };
        let brokers = r
            .array(|r| {
                Ok(Broker {
                    node_id: r.i32()?,
                    host: r.string()?,
                    port: r.i32()?,
                    rack: if v >= 1 { r.nullable_string()? } else { None },
                })
            })?
            .unwrap_or_default();
        let cluster_id = if v >= 2 { r.nullable_string()? } else { None };
        let controller_id = if v >= 1 { r.i32()? } else { -1 };
        let topics = r
            .array(|r| {
                let error = r.i16()?;
                let name = r.string()?;
                let internal = if v >= 1 { r.i8()? != 0 } else { false };
                let partitions = r
                    .array(|r| {
                        Ok(MetadataPartition {
                            error: r.i16()?,
                            index: r.i32()?,
                            leader: r.i32()?,
                            leader_epoch: if v >= 7 { r.i32()? } else { -1 },
                            replicas: ints(r)?,
                            isr: ints(r)?,
                            offline: if v >= 5 { ints(r)? } else { Vec::new() },
                        })
                    })?
                    .unwrap_or_default();
                let authorized_operations = if v >= 8 { r.i32()? } else { i32::MIN };
                Ok(MetadataTopic {
                    error,
                    name,
                    internal,
                    partitions,
                    authorized_operations,
                })
            })?
            .unwrap_or_default();
        let cluster_authorized_operations = if v >= 8 { r.i32()? } else { i32::MIN };
        if r.remaining() != 0 {
            return Err(Malformed);
        }
        Ok(Self {
            throttle_ms,
            brokers,
            cluster_id,
            controller_id,
            topics,
            cluster_authorized_operations,
        })
    }

    #[must_use]
    pub fn encode(&self, version: i16) -> Vec<u8> {
        let v = version;
        let mut w = Writer::new();
        if v >= 3 {
            w = w.i32(self.throttle_ms);
        }
        w = w.i32(i32::try_from(self.brokers.len()).unwrap_or(0));
        for b in &self.brokers {
            w = w.i32(b.node_id).string(&b.host).i32(b.port);
            if v >= 1 {
                w = w.nullable_string(b.rack.as_deref());
            }
        }
        if v >= 2 {
            w = w.nullable_string(self.cluster_id.as_deref());
        }
        if v >= 1 {
            w = w.i32(self.controller_id);
        }
        w = w.i32(i32::try_from(self.topics.len()).unwrap_or(0));
        for t in &self.topics {
            w = w.i16(t.error).string(&t.name);
            if v >= 1 {
                w = w.i8(i8::from(t.internal));
            }
            w = w.i32(i32::try_from(t.partitions.len()).unwrap_or(0));
            for p in &t.partitions {
                w = w.i16(p.error).i32(p.index).i32(p.leader);
                if v >= 7 {
                    w = w.i32(p.leader_epoch);
                }
                w = put_ints(w, &p.replicas);
                w = put_ints(w, &p.isr);
                if v >= 5 {
                    w = put_ints(w, &p.offline);
                }
            }
            if v >= 8 {
                w = w.i32(t.authorized_operations);
            }
        }
        if v >= 8 {
            w = w.i32(self.cluster_authorized_operations);
        }
        w.finish()
    }
}

// ---- FindCoordinator ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorResponse {
    pub throttle_ms: i32,
    pub error: i16,
    pub error_message: Option<String>,
    pub node_id: i32,
    pub host: String,
    pub port: i32,
}

impl CoordinatorResponse {
    /// # Errors
    /// If the body doesn't have the shape of a `FindCoordinator` response.
    pub fn decode(version: i16, body: &[u8]) -> Result<Self, Malformed> {
        let mut r = Reader::new(body);
        let throttle_ms = if version >= 1 { r.i32()? } else { 0 };
        let error = r.i16()?;
        let error_message = if version >= 1 {
            r.nullable_string()?
        } else {
            None
        };
        let out = Self {
            throttle_ms,
            error,
            error_message,
            node_id: r.i32()?,
            host: r.string()?,
            port: r.i32()?,
        };
        if r.remaining() != 0 {
            return Err(Malformed);
        }
        Ok(out)
    }

    #[must_use]
    pub fn encode(&self, version: i16) -> Vec<u8> {
        let mut w = Writer::new();
        if version >= 1 {
            w = w.i32(self.throttle_ms);
        }
        w = w.i16(self.error);
        if version >= 1 {
            w = w.nullable_string(self.error_message.as_deref());
        }
        w.i32(self.node_id)
            .string(&self.host)
            .i32(self.port)
            .finish()
    }
}

// ---- OffsetFetch ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedPartition {
    pub index: i32,
    pub offset: i64,
    pub leader_epoch: i32,
    pub metadata: Option<String>,
    pub error: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetFetchResponse {
    pub throttle_ms: i32,
    pub topics: Vec<(String, Vec<FetchedPartition>)>,
    pub error: i16,
}

impl OffsetFetchResponse {
    /// # Errors
    /// If the body doesn't have the shape of an `OffsetFetch` response.
    pub fn decode(version: i16, body: &[u8]) -> Result<Self, Malformed> {
        let v = version;
        let mut r = Reader::new(body);
        let throttle_ms = if v >= 3 { r.i32()? } else { 0 };
        let topics = r
            .array(|r| {
                let name = r.string()?;
                let parts = r
                    .array(|r| {
                        Ok(FetchedPartition {
                            index: r.i32()?,
                            offset: r.i64()?,
                            leader_epoch: if v >= 5 { r.i32()? } else { -1 },
                            metadata: r.nullable_string()?,
                            error: r.i16()?,
                        })
                    })?
                    .unwrap_or_default();
                Ok((name, parts))
            })?
            .unwrap_or_default();
        let error = if v >= 2 { r.i16()? } else { 0 };
        if r.remaining() != 0 {
            return Err(Malformed);
        }
        Ok(Self {
            throttle_ms,
            topics,
            error,
        })
    }

    #[must_use]
    pub fn encode(&self, version: i16) -> Vec<u8> {
        let v = version;
        let mut w = Writer::new();
        if v >= 3 {
            w = w.i32(self.throttle_ms);
        }
        w = w.i32(i32::try_from(self.topics.len()).unwrap_or(0));
        for (name, parts) in &self.topics {
            w = w.string(name).i32(i32::try_from(parts.len()).unwrap_or(0));
            for p in parts {
                w = w.i32(p.index).i64(p.offset);
                if v >= 5 {
                    w = w.i32(p.leader_epoch);
                }
                w = w.nullable_string(p.metadata.as_deref()).i16(p.error);
            }
        }
        if v >= 2 {
            w = w.i16(self.error);
        }
        w.finish()
    }
}

// ---- ApiVersions --------------------------------------------------------------------

/// What the worker offers clients: its own table, narrowed to what the broker
/// supports. `upstream` maps an API key to the broker's `(min, max)`.
#[must_use]
pub fn offered_versions(upstream: &BTreeMap<i16, (i16, i16)>) -> Vec<(i16, i16, i16)> {
    api::SUPPORTED
        .iter()
        .filter_map(|&(key, lo, hi)| {
            let (blo, bhi) = upstream.get(&key).copied()?;
            let (lo, hi) = (lo.max(blo), hi.min(bhi));
            (lo <= hi).then_some((key, lo, hi))
        })
        .collect()
}

/// The answer to `ApiVersions` at `version` (0 to 2), or for an unsupported
/// version (`error` 35) always in the version-0 shape, as brokers do.
#[must_use]
pub fn api_versions_response(version: i16, error: i16, offered: &[(i16, i16, i16)]) -> Vec<u8> {
    let mut w = Writer::new()
        .i16(error)
        .i32(i32::try_from(offered.len()).unwrap_or(0));
    for &(key, lo, hi) in offered {
        w = w.i16(key).i16(lo).i16(hi);
    }
    if error == error::NONE && version >= 1 {
        w = w.i32(0); // throttle_time_ms
    }
    w.finish()
}

/// Read a broker's answer to `ApiVersions` v0 (what the worker asks).
///
/// # Errors
/// If the body is malformed or the broker answered with an error.
pub fn parse_api_versions_v0(body: &[u8]) -> Result<BTreeMap<i16, (i16, i16)>, Malformed> {
    let mut r = Reader::new(body);
    if r.i16()? != error::NONE {
        return Err(Malformed);
    }
    Ok(r.array(|r| Ok((r.i16()?, (r.i16()?, r.i16()?))))?
        .unwrap_or_default()
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn produce_request(version: i16, acks: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
        let _ = version;
        let mut w = Writer::new()
            .nullable_string(None)
            .i16(acks)
            .i32(5000)
            .i32(i32::try_from(topics.len()).unwrap());
        for (name, parts) in topics {
            w = w.string(name).i32(i32::try_from(parts.len()).unwrap());
            for p in *parts {
                w = w.i32(*p).bytes(b"record-batch-bytes");
            }
        }
        w.finish()
    }

    #[test]
    fn produce_topics_are_found_and_cut_out() {
        let body = produce_request(
            8,
            1,
            &[("orders", &[0, 1]), ("secret", &[0]), ("logs", &[2])],
        );
        let Parsed::Produce {
            acks,
            transactional,
            topics,
        } = parse_request(api::PRODUCE, 8, &body).expect("parses")
        else {
            panic!("wrong variant")
        };
        assert_eq!((acks, transactional), (1, false));
        let names: Vec<_> = topics.spans.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["orders", "secret", "logs"]);
        assert_eq!(topics.spans[0].partitions, [0, 1]);
        // Cutting out "secret" leaves a request that parses to the other two.
        let cut = topics.cut(&body, &[true, false, true]);
        let Parsed::Produce { topics: after, .. } =
            parse_request(api::PRODUCE, 8, &cut).expect("still parses")
        else {
            panic!()
        };
        let names: Vec<_> = after.spans.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["orders", "logs"]);
        assert!(!cut.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn a_transactional_produce_is_marked() {
        let mut w = Writer::new()
            .nullable_string(Some("tx-1"))
            .i16(1)
            .i32(1)
            .i32(0)
            .finish();
        w.extend_from_slice(&[]);
        let Parsed::Produce { transactional, .. } =
            parse_request(api::PRODUCE, 3, &w).expect("parses")
        else {
            panic!()
        };
        assert!(transactional);
    }

    #[test]
    fn fetch_reads_every_version_shape() {
        for v in 4..=11 {
            let mut w = Writer::new().i32(-1).i32(500).i32(1).i32(1 << 20).i8(0);
            if v >= 7 {
                w = w.i32(0).i32(-1);
            }
            w = w.i32(1).string("orders").i32(1).i32(3);
            if v >= 9 {
                w = w.i32(-1);
            }
            w = w.i64(42);
            if v >= 5 {
                w = w.i64(0);
            }
            w = w.i32(1 << 20);
            if v >= 7 {
                w = w.i32(0); // forgotten topics
            }
            if v >= 11 {
                w = w.string("");
            }
            let body = w.finish();
            let Parsed::Fetch { topics } = parse_request(api::FETCH, v, &body).expect("parses")
            else {
                panic!()
            };
            assert_eq!(topics.spans[0].name, "orders", "v{v}");
            assert_eq!(topics.spans[0].partitions, [3], "v{v}");
            // The tail after the topics survives a cut.
            let cut = topics.cut(&body, &[true]);
            assert_eq!(cut, body, "v{v}");
        }
    }

    #[test]
    fn list_offsets_offset_commit_and_offset_fetch_parse() {
        let mut w = Writer::new().i32(-1).i8(0).i32(1).string("orders").i32(2);
        w = w.i32(0).i64(-1).i32(1).i64(-2);
        let Parsed::ListOffsets { topics } =
            parse_request(api::LIST_OFFSETS, 2, &w.finish()).expect("parses")
        else {
            panic!()
        };
        assert_eq!(topics.spans[0].partitions, [0, 1]);

        let commit = Writer::new()
            .string("g1")
            .i32(3)
            .string("m")
            .i64(-1)
            .i32(1)
            .string("orders")
            .i32(1)
            .i32(0)
            .i64(10)
            .nullable_string(None)
            .finish();
        let Parsed::OffsetCommit { group, topics } =
            parse_request(api::OFFSET_COMMIT, 2, &commit).expect("parses")
        else {
            panic!()
        };
        assert_eq!(group, "g1");
        assert_eq!(topics.spans[0].name, "orders");

        let all = Writer::new().string("g1").i32(-1).finish();
        let Parsed::OffsetFetch { topics: None, .. } =
            parse_request(api::OFFSET_FETCH, 2, &all).expect("parses")
        else {
            panic!("a null topics array means every topic")
        };
        let some = Writer::new()
            .string("g1")
            .i32(1)
            .string("orders")
            .i32(1)
            .i32(0)
            .finish();
        let Parsed::OffsetFetch {
            topics: Some(t), ..
        } = parse_request(api::OFFSET_FETCH, 2, &some).expect("parses")
        else {
            panic!()
        };
        assert_eq!(t.spans[0].partitions, [0]);
    }

    #[test]
    fn group_and_coordinator_requests_name_their_group() {
        for key in [
            api::JOIN_GROUP,
            api::HEARTBEAT,
            api::LEAVE_GROUP,
            api::SYNC_GROUP,
        ] {
            let body = Writer::new().string("reports").i32(1).finish();
            assert_eq!(
                parse_request(key, 0, &body),
                Ok(Parsed::Group {
                    group: "reports".into()
                })
            );
        }
        let fc = Writer::new().string("reports").i8(0).finish();
        assert_eq!(
            parse_request(api::FIND_COORDINATOR, 1, &fc),
            Ok(Parsed::FindCoordinator {
                key: "reports".into(),
                key_type: 0
            })
        );
        let txn = Writer::new().string("tx").i8(1).finish();
        assert!(matches!(
            parse_request(api::FIND_COORDINATOR, 2, &txn),
            Ok(Parsed::FindCoordinator { key_type: 1, .. })
        ));
    }

    #[test]
    fn create_and_delete_topics_parse() {
        let create = Writer::new()
            .i32(1)
            .string("new-topic")
            .i32(3)
            .i16(2)
            .i32(0) // assignments
            .i32(1)
            .string("retention.ms")
            .nullable_string(Some("1000"))
            .i32(30_000)
            .i8(0)
            .finish();
        let Parsed::CreateTopics { topics } =
            parse_request(api::CREATE_TOPICS, 1, &create).expect("parses")
        else {
            panic!()
        };
        assert_eq!(topics.spans[0].name, "new-topic");
        assert_eq!(topics.cut(&create, &[false])[..4], [0, 0, 0, 0]);
        let delete = Writer::new()
            .i32(2)
            .string("a")
            .string("b")
            .i32(1000)
            .finish();
        let Parsed::DeleteTopics { topics } =
            parse_request(api::DELETE_TOPICS, 1, &delete).expect("parses")
        else {
            panic!()
        };
        assert_eq!(
            topics
                .spans
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn truncated_requests_are_malformed() {
        let body = produce_request(8, 1, &[("orders", &[0])]);
        for cut in 0..body.len() {
            assert!(
                parse_request(api::PRODUCE, 8, &body[..cut]).is_err(),
                "cut at {cut}"
            );
        }
        assert!(parse_request(99, 0, &[]).is_err());
    }

    #[test]
    fn metadata_requests_can_be_narrowed_and_stop_creating_topics() {
        // v4: topics, allow_auto_topic_creation.
        let body = Writer::new().i32(2).string("a").string("b").i8(1).finish();
        let names = ["a".to_owned()];
        let out = rewrite_metadata_request(4, &body, Some(&names), false).expect("rewritten");
        let Parsed::Metadata { names: Some(n) } =
            parse_request(api::METADATA, 4, &out).expect("parses")
        else {
            panic!()
        };
        assert_eq!(n, ["a"]);
        assert_eq!(*out.last().expect("flag"), 0, "auto creation turned off");
        let kept = rewrite_metadata_request(4, &body, None, true).expect("rewritten");
        assert_eq!(&kept[..4], [0xFF; 4], "all topics stays null");
        assert_eq!(*kept.last().expect("flag"), 1);
    }

    fn sample_metadata(v: i16) -> MetadataResponse {
        MetadataResponse {
            throttle_ms: 0,
            brokers: vec![
                Broker {
                    node_id: 1,
                    host: "kafka-1".into(),
                    port: 9092,
                    rack: None,
                },
                Broker {
                    node_id: 2,
                    host: "kafka-2".into(),
                    port: 9092,
                    rack: Some("a".into()),
                },
            ],
            cluster_id: if v >= 2 { Some("cid".into()) } else { None },
            controller_id: if v >= 1 { 1 } else { -1 },
            topics: vec![MetadataTopic {
                error: 0,
                name: "orders".into(),
                internal: false,
                partitions: vec![MetadataPartition {
                    error: 0,
                    index: 0,
                    leader: 2,
                    leader_epoch: if v >= 7 { 4 } else { -1 },
                    replicas: vec![2, 1],
                    isr: vec![2, 1],
                    offline: Vec::new(),
                }],
                authorized_operations: if v >= 8 { 7 } else { i32::MIN },
            }],
            cluster_authorized_operations: if v >= 8 { 0 } else { i32::MIN },
        }
    }

    #[test]
    fn metadata_responses_round_trip_in_every_version() {
        for v in 1..=8 {
            let m = sample_metadata(v);
            let bytes = m.encode(v);
            assert_eq!(MetadataResponse::decode(v, &bytes), Ok(m), "v{v}");
            // Trailing junk is refused rather than ignored.
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(MetadataResponse::decode(v, &longer).is_err(), "v{v}");
        }
    }

    #[test]
    fn coordinator_and_offset_fetch_responses_round_trip() {
        for v in 0..=2 {
            let c = CoordinatorResponse {
                throttle_ms: 0,
                error: 0,
                error_message: None,
                node_id: 3,
                host: "kafka-3".into(),
                port: 9092,
            };
            assert_eq!(CoordinatorResponse::decode(v, &c.encode(v)), Ok(c), "v{v}");
        }
        for v in 1..=5 {
            let r = OffsetFetchResponse {
                throttle_ms: 0,
                topics: vec![(
                    "orders".into(),
                    vec![FetchedPartition {
                        index: 0,
                        offset: 5,
                        leader_epoch: if v >= 5 { 1 } else { -1 },
                        metadata: None,
                        error: 0,
                    }],
                )],
                error: 0,
            };
            assert_eq!(OffsetFetchResponse::decode(v, &r.encode(v)), Ok(r), "v{v}");
        }
    }

    fn empty_produce_response(v: i16) -> Vec<u8> {
        empty_topic_response(api::PRODUCE, v)
    }

    #[test]
    fn refused_topics_are_appended_to_each_response_shape() {
        let span = TopicSpan {
            name: "secret".into(),
            start: 0,
            end: 0,
            partitions: vec![0, 1],
        };
        for (key, lo, hi) in [
            (api::PRODUCE, 3, 8),
            (api::FETCH, 4, 11),
            (api::LIST_OFFSETS, 1, 5),
            (api::OFFSET_COMMIT, 2, 7),
            (api::OFFSET_FETCH, 1, 5),
            (api::CREATE_TOPICS, 0, 4),
            (api::DELETE_TOPICS, 0, 3),
        ] {
            for v in lo..=hi {
                let base = if key == api::OFFSET_FETCH {
                    OffsetFetchResponse {
                        throttle_ms: 0,
                        topics: Vec::new(),
                        error: 0,
                    }
                    .encode(v)
                } else {
                    empty_topic_response(key, v)
                };
                let out =
                    append_refused(key, v, &base, &[&span], error::TOPIC_AUTHORIZATION_FAILED)
                        .unwrap_or_else(|e| panic!("{} v{v}: {e}", api::name(key)));
                assert!(out.len() > base.len(), "{} v{v}", api::name(key));
                if key == api::OFFSET_FETCH {
                    let r = OffsetFetchResponse::decode(v, &out).expect("still decodes");
                    assert_eq!(r.topics[0].0, "secret");
                    assert_eq!(r.topics[0].1.len(), 2);
                    assert_eq!(r.topics[0].1[0].error, 29);
                    assert_eq!(r.error, 0);
                }
            }
        }
    }

    #[test]
    fn a_refused_topic_is_added_to_a_response_that_already_has_others() {
        // A produce response for "orders" partition 0, then ours for "secret".
        let v = 8;
        let base = Writer::new()
            .i32(1)
            .string("orders")
            .i32(1)
            .i32(0)
            .i16(0)
            .i64(100)
            .i64(-1)
            .i64(0)
            .i32(0)
            .nullable_string(None)
            .i32(7) // throttle_time_ms
            .finish();
        let span = TopicSpan {
            name: "secret".into(),
            start: 0,
            end: 0,
            partitions: vec![0],
        };
        let out = append_refused(api::PRODUCE, v, &base, &[&span], 29).expect("appended");
        let mut r = Reader::new(&out);
        assert_eq!(r.i32(), Ok(2));
        assert_eq!(r.string().as_deref(), Ok("orders"));
        // ... the throttle time is still the last four bytes.
        assert_eq!(out[out.len() - 4..], [0, 0, 0, 7]);
        assert!(out.windows(6).any(|w| w == b"secret"));
        assert_eq!(empty_produce_response(v).len(), 8);
    }

    #[test]
    fn whole_request_refusals_have_the_shape_of_the_api() {
        let group = Parsed::Group { group: "g".into() };
        for (key, lo, hi) in [
            (api::JOIN_GROUP, 0, 5),
            (api::HEARTBEAT, 0, 3),
            (api::LEAVE_GROUP, 0, 3),
            (api::SYNC_GROUP, 0, 3),
        ] {
            for v in lo..=hi {
                let body = refusal_response(key, v, &group, error::GROUP_AUTHORIZATION_FAILED)
                    .expect("builds");
                assert!(!body.is_empty());
                assert!(
                    body.windows(2).any(|w| w == [0, 30]),
                    "{} v{v} carries error 30",
                    api::name(key)
                );
            }
        }
        let fc = refusal_response(api::FIND_COORDINATOR, 1, &group, 30).expect("builds");
        let parsed = CoordinatorResponse::decode(1, &fc).expect("decodes");
        assert_eq!((parsed.error, parsed.node_id), (30, -1));
        let fc0 = refusal_response(api::FIND_COORDINATOR, 0, &group, 30).expect("builds");
        assert_eq!(
            CoordinatorResponse::decode(0, &fc0).expect("decodes").error,
            30
        );
        let txn = refusal_response(api::INIT_PRODUCER_ID, 1, &group, 53).expect("builds");
        assert_eq!(txn.len(), 4 + 2 + 8 + 2);
        // A refused fetch lists every topic with the error.
        let body = Writer::new()
            .i32(-1)
            .i32(0)
            .i32(1)
            .i32(1)
            .i8(0)
            .i32(1)
            .string("secret")
            .i32(1)
            .i32(0)
            .i64(0)
            .i32(1)
            .finish();
        let parsed = parse_request(api::FETCH, 4, &body).expect("parses");
        let out = refusal_response(api::FETCH, 4, &parsed, 29).expect("builds");
        assert!(out.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn api_versions_are_the_workers_table_narrowed_to_the_broker() {
        let mut upstream: BTreeMap<i16, (i16, i16)> = BTreeMap::new();
        upstream.insert(api::PRODUCE, (0, 11));
        upstream.insert(api::FETCH, (0, 6)); // lower than the worker's top
        upstream.insert(api::METADATA, (0, 12));
        upstream.insert(api::API_VERSIONS, (0, 3));
        upstream.insert(99, (0, 1)); // an API the worker doesn't relay
        let offered = offered_versions(&upstream);
        assert!(offered.contains(&(api::PRODUCE, 3, 8)));
        assert!(offered.contains(&(api::FETCH, 4, 6)));
        assert!(offered.contains(&(api::METADATA, 1, 8)));
        assert!(offered.iter().all(|(k, _, _)| *k != 99));
        assert!(
            offered.iter().all(|(k, _, _)| *k != api::OFFSET_COMMIT),
            "an API the broker lacks isn't offered"
        );
        let v2 = api_versions_response(2, 0, &offered);
        let mut r = Reader::new(&v2);
        assert_eq!(r.i16(), Ok(0));
        let n = r.array_len().expect("array").expect("not null");
        assert_eq!(n, offered.len());
        // The unsupported-version answer is v0-shaped: error then the array, no throttle.
        let unsupported = api_versions_response(3, error::UNSUPPORTED_VERSION, &offered);
        assert_eq!(unsupported.len(), 2 + 4 + 6 * offered.len());
        assert_eq!(
            parse_api_versions_v0(&api_versions_response(0, 0, &offered))
                .expect("v0")
                .len(),
            offered.len()
        );
    }
}
