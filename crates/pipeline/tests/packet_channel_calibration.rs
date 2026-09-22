//! The packet oracle's OBSERVATION CHANNEL, measured (devlog 0040, `--probe-pktw`).
//!
//! 0039 reads an absent or truncated sentinel run as an OOB packet write. That reading
//! rests on a claim about the channel: `bpf_prog_test_run_skb` copies back only
//! `[0, skb->len)`, so a store past `data_end` lands in skb tailroom and never returns.
//! The claim was ARGUED from the kernel source, never OBSERVED — a sound verifier
//! rejects every OOB store, so 0039 exercised only the channel's POSITIVE half (a byte
//! inside the packet comes back). The next leg (store-location desync) will assert "the
//! verifier proved X, the store landed at Y"; trusting that "landed at Y" requires the
//! channel to resolve bytes precisely, so this precondition is measured here first.
//!
//! The probe moves the WINDOW instead of the store — `bpf_skb_change_tail()` shrinks
//! `skb->len` AFTER the store has run, leaving an already-written byte beyond the
//! returned length. That is the exact geometry of an OOB store, reached with only
//! ACCEPTED programs, so it needs no buggy verifier.
//!
//!   probe#pktw.win32     in=32, store 31, no trim  -> out_size=32, store_off=31
//!   probe#pktw.win40     in=40, store 31, no trim  -> out_size=40, store_off=31
//!   probe#pktw.trim.o19  in=32, store 19, trim 20  -> out_size=20, store_off=19
//!   probe#pktw.trim.o20  in=32, store 20, trim 20  -> out_size=20, store_off=none
//!
//! The last two are the byte-precise edge: identical shape, identical shrink, store
//! offsets ONE apart, opposite observability — so "absent" is positional and not an
//! artefact of change_tail disturbing the data. `tail_zero=1` on every arm reports the
//! positive half of the same claim: the pre-zeroed output buffer is still zero beyond
//! `out_size`, so a byte out there can never be MISREAD as a sentinel either.

const PROBE: &str = include_str!("fixtures/volume/probe-pktw-4.log");

#[derive(Debug, PartialEq)]
struct Channel {
    name: String,
    accepted: bool,
    in_size: u32,
    out_size: u32,
    retval: u32,
    store_off: Option<u32>,
    tail_zero: bool,
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing {key} in {line:?}"))
}

fn arms() -> Vec<Channel> {
    PROBE
        .split("===PROG ")
        .skip(1)
        .map(|block| {
            let name = block.split_whitespace().next().unwrap().to_string();
            let result = block.lines().find(|l| l.starts_with("RESULT ")).expect("RESULT");
            let ch = block.lines().find(|l| l.starts_with("CHANNEL ")).expect("CHANNEL");
            let raw_off = field(ch, "store_off=");
            Channel {
                name,
                accepted: field(result, "decision=") == "accept",
                in_size: field(ch, "in_size=").parse().unwrap(),
                out_size: field(ch, "out_size=").parse().unwrap(),
                retval: field(ch, "retval=").parse().unwrap(),
                store_off: if raw_off == "none" { None } else { Some(raw_off.parse().unwrap()) },
                tail_zero: field(ch, "tail_zero=") == "1",
            }
        })
        .collect()
}

fn arm(name: &str) -> Channel {
    arms().into_iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no arm {name}"))
}

#[test]
fn all_four_arms_ran_and_were_accepted() {
    let all = arms();
    assert_eq!(all.len(), 4, "four probe arms: {all:#?}");
    for c in &all {
        assert!(c.accepted, "the probe measures the channel, not the decision: {c:?}");
        // change_tail returns 0 on success; the plain arms return a literal 0.
        assert_eq!(c.retval, 0, "the program (and its change_tail) succeeded: {c:?}");
    }
}

/// The window is exactly the packet: everything the program can legally write comes back.
#[test]
fn the_returned_window_is_exactly_the_packet() {
    let c = arm("probe#pktw.win32");
    assert_eq!(c.in_size, 32);
    assert_eq!(c.out_size, 32, "out_size == skb->len == M: {c:?}");
    assert_eq!(c.store_off, Some(31), "the last in-bounds byte comes back: {c:?}");
}

/// out_size is not a constant the harness happens to agree with — it MOVES with skb->len.
#[test]
fn the_window_tracks_skb_len() {
    let (a, b) = (arm("probe#pktw.win32"), arm("probe#pktw.win40"));
    assert_eq!(b.in_size, 40);
    assert_eq!(b.out_size, b.in_size, "the window followed the longer packet: {b:?}");
    assert_ne!(a.out_size, b.out_size, "same program, different window: {a:?} {b:?}");
    assert_eq!(b.store_off, Some(31), "the store did not move: {b:?}");
}

/// Positive half at the edge: the LAST byte inside the window is resolved.
#[test]
fn the_last_returned_byte_is_resolved() {
    let c = arm("probe#pktw.trim.o19");
    assert_eq!(c.out_size, 20, "change_tail shrank the window: {c:?}");
    assert_eq!(c.store_off, Some(19), "byte 19 = out_size-1 is visible: {c:?}");
}

/// NEGATIVE half — the half 0039 could never reach, because a sound verifier rejects
/// every OOB store. The byte at index == out_size WAS physically written into the packet
/// buffer, and the channel does not return it: exactly what the oracle reads as OOB.
#[test]
fn a_byte_past_the_window_is_invisible() {
    let c = arm("probe#pktw.trim.o20");
    assert_eq!(c.out_size, 20, "change_tail shrank the window: {c:?}");
    assert_eq!(c.store_off, None, "byte 20 = out_size was written yet never returned: {c:?}");
}

/// The two trim arms differ by ONE byte of store offset and nothing else, and land on
/// opposite sides of observability — so the edge is byte-precise, and "absent" is
/// positional rather than an artefact of change_tail touching the data.
#[test]
fn the_window_edge_is_byte_precise() {
    let (inside, outside) = (arm("probe#pktw.trim.o19"), arm("probe#pktw.trim.o20"));
    assert_eq!(inside.in_size, outside.in_size, "same input packet");
    assert_eq!(inside.out_size, outside.out_size, "same shrunk window");
    assert_eq!(
        outside.store_off.map_or(20, |o| o),
        inside.store_off.unwrap() + 1,
        "the two stores are exactly one byte apart"
    );
    assert!(inside.store_off.is_some() && outside.store_off.is_none(),
        "one byte apart, opposite observability: {inside:?} {outside:?}");
}

/// The other direction of the same claim: nothing beyond the window can be MISREAD as a
/// sentinel, because the pre-zeroed output buffer is left untouched out there.
#[test]
fn the_output_buffer_stays_zero_beyond_the_window() {
    for c in arms() {
        assert!(c.tail_zero, "bytes [out_size, 64) still zero after the run: {c:?}");
    }
}
