//! Receipt mutations must never replay an already-applied request.
use crisp_internxt::{HttpConfig, InternxtNativeClient, TransferConfig, HTTP_USER_AGENT};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Trash,
    Restore,
    TrashFolder,
    RestoreFolder,
    TrashEscaped,
    RestoreEscaped,
}

fn read_request(stream: &mut TcpStream) -> String {
    // Windows accepted sockets can inherit the listener's nonblocking mode.
    // Poll accept independently, but read each request in bounded blocking mode.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0, "request closed before its complete body");
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return String::from_utf8(bytes).unwrap();
            }
        }
    }
}

#[test]
fn accepted_nonblocking_stream_reads_the_entire_fragmented_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    // Reproduce the inherited Windows listener mode on every platform.
    accepted.set_nonblocking(true).unwrap();
    assert_eq!(
        accepted.peek(&mut [0u8; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let writer = thread::spawn(move || {
        // Leave the reader waiting for both the first bytes and the final body;
        // no complete request may be assumed available immediately after accept.
        thread::sleep(Duration::from_millis(50));
        client
            .write_all(b"POST /fixture HTTP/1.1\r\nContent-Length: 4\r\n")
            .unwrap();
        thread::sleep(Duration::from_millis(25));
        client.write_all(b"\r\nbody").unwrap();
    });
    let request = read_request(&mut accepted);
    writer.join().unwrap();
    assert_eq!(
        request,
        "POST /fixture HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody"
    );
    assert_eq!(
        accepted.read_timeout().unwrap(),
        Some(Duration::from_secs(1))
    );
}

/// status=None means the mutation was received completely, then its response
/// was lost. All attempted HTTP requests are counted, including redirects.
fn fixture(
    mutation: Mutation,
    status: Option<u16>,
    delay: Duration,
    timeout: Duration,
    proxy: bool,
) -> (anyhow::Result<()>, Vec<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let server = {
        let requests = requests.clone();
        let done = done.clone();
        let location = format!("{base}/replayed");
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        requests.lock().unwrap().push(read_request(&mut stream));
                        if let Some(status) = status {
                            thread::sleep(delay);
                            stream
                                .set_write_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let redirect = if (300..400).contains(&status) {
                                format!("Location: {location}\r\n")
                            } else {
                                String::new()
                            };
                            let _ = write!(stream, "HTTP/1.1 {status} Fixture\r\n{redirect}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if done.load(Ordering::Acquire) {
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "client failed to finish the bounded fixture"
                        );
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            }
        })
    };
    let config = TransferConfig {
        request_timeout: timeout,
        ..TransferConfig::default()
    };
    let http = if proxy {
        HttpConfig {
            proxy_url: Some(base.clone()),
            proxy_username: Some("fixture-user".into()),
            proxy_password: Some("fixture-password".into()),
        }
    } else {
        HttpConfig::default()
    };
    let endpoint = if proxy {
        "http://provider.invalid/drive"
    } else {
        &base
    };
    let client =
        InternxtNativeClient::new_with_config_and_http(endpoint, "fixture-bearer", config, &http)
            .unwrap();
    let result = match mutation {
        Mutation::Trash => client.trash_once("object-id", "file"),
        Mutation::Restore => {
            client.restore_from_trash_once("object-id", "files", "recorded-folder")
        }
        Mutation::TrashFolder => client.trash_once("folder-id", "folder"),
        Mutation::RestoreFolder => {
            client.restore_from_trash_once("folder-id", "folders", "recorded-parent")
        }
        Mutation::TrashEscaped => client.trash_once("object/id #?%", "file"),
        Mutation::RestoreEscaped => {
            client.restore_from_trash_once("object/id #?%", "files", "parent/id #?%")
        }
    };
    done.store(true, Ordering::Release);
    server.join().unwrap();
    let recorded = requests.lock().unwrap().clone();
    (result, recorded)
}

#[test]
fn gateway_failures_are_one_shot_for_trash_and_restore() {
    for mutation in [Mutation::Trash, Mutation::Restore] {
        for status in [502, 503, 504] {
            let (result, requests) = fixture(
                mutation,
                Some(status),
                Duration::ZERO,
                Duration::from_secs(1),
                false,
            );
            assert!(result.is_err(), "{mutation:?} HTTP {status}");
            assert_eq!(requests.len(), 1, "{mutation:?} HTTP {status} replayed");
        }
    }
}

#[test]
fn lost_response_after_complete_request_is_not_replayed() {
    for mutation in [Mutation::Trash, Mutation::Restore] {
        let (result, requests) = fixture(
            mutation,
            None,
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        );
        assert!(result.is_err());
        assert_eq!(
            requests.len(),
            1,
            "{mutation:?} replayed after uncertain completion"
        );
    }
}

#[test]
fn redirects_are_rejected_without_a_second_mutation() {
    for mutation in [Mutation::Trash, Mutation::Restore] {
        for status in [301, 302, 303, 307, 308] {
            let (result, requests) = fixture(
                mutation,
                Some(status),
                Duration::ZERO,
                Duration::from_secs(1),
                false,
            );
            assert!(result.is_err());
            assert_eq!(requests.len(), 1, "{mutation:?} followed HTTP {status}");
        }
    }
}

#[test]
fn request_timeout_is_preserved_and_does_not_replay() {
    for mutation in [Mutation::Trash, Mutation::Restore] {
        let (result, requests) = fixture(
            mutation,
            Some(200),
            Duration::from_millis(400),
            Duration::from_millis(150),
            false,
        );
        assert!(result.unwrap_err().chain().any(|cause| cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout)));
        assert_eq!(requests.len(), 1);
    }
}

#[test]
fn configured_proxy_auth_and_exact_payload_are_preserved() {
    for mutation in [Mutation::Trash, Mutation::Restore] {
        let (result, requests) = fixture(
            mutation,
            Some(200),
            Duration::ZERO,
            Duration::from_secs(1),
            true,
        );
        result.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer fixture-bearer"));
        let header = |name: &str| {
            request.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name).then(|| value.trim())
            })
        };
        let proxy_auth = "Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtcGFzc3dvcmQ=";
        assert_eq!(header("proxy-authorization"), Some(proxy_auth));
        assert_eq!(header("user-agent"), Some(HTTP_USER_AGENT));
        assert!(lower.contains("internxt-client: internxt-cli"));
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        match mutation {
            Mutation::Trash => {
                assert!(
                    request.starts_with("POST http://provider.invalid/drive/storage/trash/add ")
                );
                assert_eq!(
                    body,
                    serde_json::json!({"items":[{"uuid":"object-id","type":"file"}]})
                );
            }
            Mutation::Restore => {
                assert!(request.starts_with("PATCH http://provider.invalid/drive/files/object-id "));
                assert_eq!(
                    body,
                    serde_json::json!({"destinationFolder":"recorded-folder"})
                );
            }
            _ => unreachable!("proxy fixture covers file operations"),
        }
    }
}

#[test]
fn invalid_receipt_identity_is_rejected_before_transport() {
    let client = InternxtNativeClient::new("http://127.0.0.1:1", "fixture-bearer").unwrap();
    for uuid in ["", ".", ".."] {
        assert!(client
            .trash_once(uuid, "file")
            .unwrap_err()
            .to_string()
            .contains("invalid one-shot"));
        assert!(client
            .restore_from_trash_once(uuid, "files", "parent")
            .unwrap_err()
            .to_string()
            .contains("invalid one-shot"));
    }
    assert!(client
        .trash_once("object", "files")
        .unwrap_err()
        .to_string()
        .contains("invalid one-shot"));
    assert!(client
        .restore_from_trash_once("object", "file", "parent")
        .unwrap_err()
        .to_string()
        .contains("invalid one-shot"));
    assert!(client
        .restore_from_trash_once("object", "files", "")
        .unwrap_err()
        .to_string()
        .contains("invalid one-shot"));
}

#[test]
fn folders_preserve_kind_and_exact_destination() {
    for mutation in [Mutation::TrashFolder, Mutation::RestoreFolder] {
        let (result, requests) = fixture(
            mutation,
            Some(200),
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        );
        result.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        match mutation {
            Mutation::TrashFolder => {
                assert!(request.starts_with("POST /storage/trash/add "));
                assert_eq!(
                    body,
                    serde_json::json!({"items":[{"uuid":"folder-id","type":"folder"}]})
                );
            }
            Mutation::RestoreFolder => {
                assert!(request.starts_with("PATCH /folders/folder-id "));
                assert_eq!(
                    body,
                    serde_json::json!({"destinationFolder":"recorded-parent"})
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn opaque_identifiers_are_encoded_in_paths_and_preserved_in_json() {
    for mutation in [Mutation::TrashEscaped, Mutation::RestoreEscaped] {
        let (result, requests) = fixture(
            mutation,
            Some(200),
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        );
        result.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        match mutation {
            Mutation::TrashEscaped => {
                assert!(request.starts_with("POST /storage/trash/add "));
                assert_eq!(
                    body,
                    serde_json::json!({"items":[{"uuid":"object/id #?%","type":"file"}]})
                );
            }
            Mutation::RestoreEscaped => {
                assert!(request.starts_with("PATCH /files/object%2Fid%20%23%3F%25 "));
                assert_eq!(
                    body,
                    serde_json::json!({"destinationFolder":"parent/id #?%"})
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn unauthorized_does_not_refresh_auth_or_replay_the_mutation() {
    for mutation in [
        Mutation::Trash,
        Mutation::Restore,
        Mutation::TrashFolder,
        Mutation::RestoreFolder,
    ] {
        let (result, requests) = fixture(
            mutation,
            Some(401),
            Duration::ZERO,
            Duration::from_secs(1),
            false,
        );
        assert!(result.is_err());
        assert_eq!(
            requests.len(),
            1,
            "{mutation:?} refreshed or replayed after 401"
        );
        assert!(!requests[0].contains("/users/refresh"));
    }
}

fn overlay_fixture(added: bool, outcome: Option<u16>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let server = {
        let requests = requests.clone();
        let done = done.clone();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_request(&mut stream);
                        let first = request.lines().next().unwrap();
                        let (status, body) = if first.starts_with("POST /folders ") {
                            (Some(200), r#"{"uuid":"folder-id"}"#)
                        } else if first.starts_with("POST /storage/trash/add ") {
                            (if added { outcome } else { Some(200) }, "{}")
                        } else if first.starts_with("PATCH /folders/folder-id ") {
                            (outcome, "{}")
                        } else if first.starts_with("GET /folders/content/parent/folders?") {
                            (
                                Some(200),
                                if added {
                                    r#"{"result":[]}"#
                                } else {
                                    r#"{"result":[{"uuid":"folder-id","plainName":"Folder"}]}"#
                                },
                            )
                        } else if first.starts_with("GET /folders/content/parent/files?") {
                            (Some(200), r#"{"result":[]}"#)
                        } else {
                            panic!("unexpected overlay fixture route: {first}");
                        };
                        requests.lock().unwrap().push(request);
                        if let Some(status) = status {
                            let _ = write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if done.load(Ordering::Acquire) {
                            break;
                        }
                        assert!(Instant::now() < deadline, "overlay fixture did not finish");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("overlay fixture accept: {error}"),
                }
            }
        })
    };
    let client =
        InternxtNativeClient::new_with_timeout(base, "fixture-bearer", Duration::from_secs(1))
            .unwrap();
    if added {
        assert_eq!(
            client.create_folder("parent", "Folder").unwrap(),
            "folder-id"
        );
    } else {
        client.trash("folder-id", "folder").unwrap();
    }
    let before = client.list_folder_cached("parent").unwrap();
    if added {
        assert_eq!(before.len(), 1, "creation overlay was not seeded");
    } else {
        assert!(before.is_empty(), "hidden overlay was not seeded");
    }
    let result = if added {
        client.trash_once("folder-id", "folder")
    } else {
        client.restore_from_trash_once("folder-id", "folders", "parent")
    };
    assert_eq!(result.is_ok(), outcome == Some(200));
    let after = client.list_folder_cached("parent").unwrap();
    done.store(true, Ordering::Release);
    server.join().unwrap();
    if added {
        assert!(
            after.is_empty(),
            "receipt attempt retained synthetic creation state"
        );
    } else {
        assert_eq!(
            after.len(),
            1,
            "receipt attempt retained synthetic hidden state"
        );
        assert_eq!(after[0].uuid, "folder-id");
    }
    let recorded = requests.lock().unwrap();
    assert_eq!(
        recorded
            .iter()
            .filter(|request| request.starts_with("GET "))
            .count(),
        4,
        "listing cache was not invalidated"
    );
    let one_shot_method = if added {
        "POST /storage/trash/add "
    } else {
        "PATCH /folders/folder-id "
    };
    assert_eq!(
        recorded
            .iter()
            .filter(|request| request.starts_with(one_shot_method))
            .count(),
        1
    );
}

#[test]
fn creation_overlay_and_listing_cache_are_invalidated_on_every_receipt_outcome() {
    for outcome in [Some(200), Some(502), None] {
        overlay_fixture(true, outcome);
    }
}

#[test]
fn hidden_overlay_and_listing_cache_are_invalidated_on_every_receipt_outcome() {
    for outcome in [Some(200), Some(502), None] {
        overlay_fixture(false, outcome);
    }
}
