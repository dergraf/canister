//! The stub resolver of transparent egress (ADR-0027).
//!
//! In the workload's network namespace every name resolves to the proxy's
//! loopback address, so a client that ignores `HTTP_PROXY` still connects
//! to the proxy, which learns the real host from TLS SNI or `Host`. The
//! stub resolves nothing upstream: a name, including any data encoded in
//! its labels, never leaves the namespace.
//!
//! `A` queries get `127.0.0.1`; every other type gets an empty answer, so
//! a client asking for `AAAA` first falls back to IPv4. Anything that is
//! not a single well-formed question is dropped.

use std::net::Ipv4Addr;

use tokio::net::UdpSocket;
use tracing::debug;

/// What every name resolves to.
pub const ANSWER: Ipv4Addr = Ipv4Addr::LOCALHOST;

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const TTL_SECONDS: u32 = 5;

/// The response to one query, or `None` for something that is not a query
/// with exactly one question.
pub fn answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let is_query = flags & 0x8000 == 0;
    let questions = u16::from_be_bytes([query[4], query[5]]);
    if !is_query || questions != 1 {
        return None;
    }

    let name_end = name_end(query, HEADER_LEN)?;
    let question_end = name_end.checked_add(4).filter(|end| *end <= query.len())?;
    let qtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
    let qclass = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
    let answers: u16 = if qtype == TYPE_A && qclass == CLASS_IN {
        1
    } else {
        0
    };

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    // QR, the query's opcode and RD, RA; NOERROR.
    let response_flags = 0x8000 | (flags & 0x7900) | 0x0080;
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&answers.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&query[HEADER_LEN..question_end]);

    if answers == 1 {
        // A pointer to the question's name, then the A record.
        response.extend_from_slice(&[0xC0, HEADER_LEN as u8]);
        response.extend_from_slice(&TYPE_A.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&TTL_SECONDS.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ANSWER.octets());
    }

    Some(response)
}

/// Where the name starting at `start` ends: the offset after its zero
/// label. Compression pointers are not valid in a question.
fn name_end(packet: &[u8], start: usize) -> Option<usize> {
    let mut at = start;
    loop {
        let length = *packet.get(at)? as usize;
        if length == 0 {
            return Some(at + 1);
        }
        if length & 0xC0 != 0 {
            return None;
        }
        at = at.checked_add(length + 1)?;
    }
}

/// Answer queries on `socket` until it fails.
pub async fn serve(socket: UdpSocket) {
    let mut buffer = [0u8; 512];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        match answer(&buffer[..len]) {
            Some(response) => {
                let _ = socket.send_to(&response, peer).await;
            }
            None => debug!(
                len,
                "dns stub: dropped a packet that is not a single question"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet
    }

    #[test]
    fn an_a_query_resolves_to_the_proxy() {
        let request = query("helpdesk.example.com", TYPE_A);
        let response = answer(&request).expect("answered");

        assert_eq!(&response[0..2], &[0x12, 0x34], "the id is echoed");
        assert_eq!(response[2] & 0x80, 0x80, "it is a response");
        assert_eq!(response[3] & 0x0F, 0, "NOERROR");
        assert_eq!(&response[6..8], &[0, 1], "one answer");
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);
        assert_eq!(
            &response[HEADER_LEN..request.len()],
            &request[HEADER_LEN..],
            "the question is echoed"
        );
    }

    #[test]
    fn an_aaaa_query_gets_no_answer_so_the_client_falls_back() {
        let response = answer(&query("helpdesk.example.com", 28)).expect("answered");

        assert_eq!(&response[6..8], &[0, 0]);
        assert_eq!(response[3] & 0x0F, 0, "NOERROR, not NXDOMAIN");
    }

    #[test]
    fn anything_but_one_well_formed_question_is_dropped() {
        assert_eq!(answer(&[0; 4]), None, "too short");

        let mut two = query("a.example", TYPE_A);
        two[5] = 2;
        assert_eq!(answer(&two), None, "two questions");

        let mut response = query("a.example", TYPE_A);
        response[2] |= 0x80;
        assert_eq!(answer(&response), None, "a response, not a query");

        let truncated = query("a.example", TYPE_A);
        assert_eq!(answer(&truncated[..truncated.len() - 2]), None, "cut short");

        let mut pointer = query("a.example", TYPE_A);
        pointer[HEADER_LEN] = 0xC0;
        assert_eq!(answer(&pointer), None, "a pointer in the question");
    }
}
