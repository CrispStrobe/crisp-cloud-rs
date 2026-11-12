//! Contract tests for Internxt's current search and timestamp API
//! (drive-server-wip FuzzySearchController / UpdateFolderMetaDto).
use crisp_internxt::{
    FuzzySearchFilters, InternxtNativeClient, ItemTimes, TimestampUpdateUnsupported,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

struct Captured {
    method: String,
    path: String,
    body: serde_json::Value,
}

/// Serve one request with `reply`, returning what the client sent.
fn serve_once(reply: &'static str) -> (String, thread::JoinHandle<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap().to_owned();
        let path = parts.next().unwrap().to_owned();
        let mut length = 0;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header == "\r\n" {
                break;
            }
            if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}",
            reply.len(),
            reply
        )
        .unwrap();
        Captured {
            method,
            path,
            body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        }
    });
    (base, handle)
}

/// A base URL nothing listens on: any request would fail with a
/// connection error instead of TimestampUpdateUnsupported.
fn unreachable_base() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    base
}

#[test]
fn fuzzy_search_posts_the_encoded_text_and_parses_hits() {
    let (base, server) = serve_once(
        r#"{"data":[{"id":"l1","itemId":"u1","itemType":"file","name":"report","rank":null,"similarity":0.81}]}"#,
    );
    let client = InternxtNativeClient::new(&base, "tok").unwrap();
    let hits = client
        .fuzzy_search(" my report #2/a ", 7, &FuzzySearchFilters::default())
        .unwrap();
    let seen = server.join().unwrap();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/fuzzy/my%20report%20%232%2Fa");
    assert_eq!(seen.body, serde_json::json!({"offset": 7}));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item_id, "u1");
    assert_eq!(hits[0].item_type, "file");
    assert!(hits[0].rank.is_none());
}

#[test]
fn fuzzy_search_sends_every_filter() {
    let (base, server) = serve_once(r#"{"data":[]}"#);
    let client = InternxtNativeClient::new(&base, "tok").unwrap();
    let filters = FuzzySearchFilters {
        types: vec!["pdf".into(), "folder".into()],
        min_size: Some(10),
        max_size: Some(99),
        modified_after: Some("2026-01-01T00:00:00Z".into()),
        modified_before: Some("2026-06-30T23:59:59Z".into()),
    };
    assert!(client
        .fuzzy_search("report", 0, &filters)
        .unwrap()
        .is_empty());
    assert_eq!(
        server.join().unwrap().body,
        serde_json::json!({
            "offset": 0, "type": ["pdf", "folder"], "minSize": 10, "maxSize": 99,
            "modifiedAfter": "2026-01-01T00:00:00Z",
            "modifiedBefore": "2026-06-30T23:59:59Z"
        })
    );
}

#[test]
fn fuzzy_search_rejects_out_of_range_text_without_a_request() {
    let client = InternxtNativeClient::new(unreachable_base(), "tok").unwrap();
    for bad in ["", "ab", "  ab  ", &"x".repeat(256)] {
        let error = client
            .fuzzy_search(bad, 0, &FuzzySearchFilters::default())
            .unwrap_err();
        assert!(error.to_string().contains("3-255"), "{bad:?}: {error}");
    }
}

#[test]
fn fuzzy_search_rejects_a_body_without_data() {
    let (base, server) = serve_once(r#"{"wrong":1}"#);
    let client = InternxtNativeClient::new(&base, "tok").unwrap();
    assert!(client
        .fuzzy_search("report", 0, &FuzzySearchFilters::default())
        .is_err());
    server.join().unwrap();
}

#[test]
fn existing_item_timestamps_are_unsupported_without_a_request() {
    let client = InternxtNativeClient::new(unreachable_base(), "tok").unwrap();
    for (error, kind) in [
        (
            client
                .set_file_timestamp("f", "2021-06-01T08:15:30Z")
                .unwrap_err(),
            "file",
        ),
        (
            client
                .set_folder_timestamp("d", "2021-06-01T08:15:30Z")
                .unwrap_err(),
            "folder",
        ),
    ] {
        let typed = error
            .downcast_ref::<TimestampUpdateUnsupported>()
            .expect("typed error, not a network failure");
        assert_eq!(typed.kind, kind);
        assert!(error.to_string().contains("created or uploaded"));
    }
}

#[test]
fn folders_are_created_with_their_times() {
    let (base, server) = serve_once(r#"{"uuid":"new-folder"}"#);
    let client = InternxtNativeClient::new(&base, "tok").unwrap();
    let times = ItemTimes {
        creation_time: Some("2020-02-03T04:05:06Z".into()),
        modification_time: Some("2021-06-01T08:15:30Z".into()),
    };
    let uuid = client
        .create_folder_with_times("parent", "Docs", &times)
        .unwrap();
    let seen = server.join().unwrap();
    assert_eq!(uuid, "new-folder");
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/folders")
    );
    assert_eq!(
        seen.body,
        serde_json::json!({
            "plainName": "Docs", "parentFolderUuid": "parent",
            "creationTime": "2020-02-03T04:05:06Z",
            "modificationTime": "2021-06-01T08:15:30Z"
        })
    );
}

#[test]
fn plain_folder_creation_sends_no_times() {
    let (base, server) = serve_once(r#"{"uuid":"f"}"#);
    let client = InternxtNativeClient::new(&base, "tok").unwrap();
    client.create_folder("parent", "Docs").unwrap();
    assert_eq!(
        server.join().unwrap().body,
        serde_json::json!({"plainName": "Docs", "parentFolderUuid": "parent"})
    );
}
