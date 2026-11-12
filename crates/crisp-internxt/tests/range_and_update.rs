//! Hermetic tests for partial reads (`download_file_range`) and reader-based
//! replacement (`update_file_from_reader`) against a loopback gateway.

use crisp_internxt::{crypt, InternxtNativeClient, InternxtSession};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const INDEX: [u8; 32] = [3u8; 32];

struct Request {
    method: String,
    path: String,
    headers: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + length {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        bytes.extend_from_slice(&buffer[..read]);
    }
    let mut first = headers.lines().next().unwrap().split_whitespace();
    Request {
        method: first.next().unwrap().to_owned(),
        path: first.next().unwrap().to_owned(),
        headers: headers.to_ascii_lowercase(),
        body: bytes[header_end..header_end + length].to_vec(),
    }
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn session(address: SocketAddr) -> InternxtSession {
    InternxtSession {
        drive_api_url: format!("http://{address}"),
        network_url: format!("http://{address}"),
        email: "test@example.invalid".to_owned(),
        token: "token".to_owned(),
        new_token: "new-token".to_owned(),
        mnemonic: MNEMONIC.to_owned(),
        user_id: "user".to_owned(),
        root_folder_id: "root".to_owned(),
        bridge_user: "bridge".to_owned(),
        bucket_id: "00".repeat(12),
    }
}

/// Serves one file's metadata, download info and ciphertext object. With
/// `honor_range` the object answers `Range` with 206; otherwise it ignores the
/// header and returns the whole object with 200, as some shard URLs do.
fn spawn_download_server(
    ciphertext: Vec<u8>,
    plaintext_len: usize,
    honor_range: bool,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&ranges);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_request(&mut stream);
            match request.path.as_str() {
                "/files/file/meta" => respond(
                    &mut stream,
                    "200 OK",
                    format!(
                        r#"{{"bucket":"{}","fileId":"net","size":"{plaintext_len}"}}"#,
                        "00".repeat(12)
                    )
                    .as_bytes(),
                ),
                p if p.ends_with("/files/net/info") => respond(
                    &mut stream,
                    "200 OK",
                    format!(
                        r#"{{"shards":[{{"url":"http://{address}/object"}}],"index":"{}"}}"#,
                        hex::encode(INDEX)
                    )
                    .as_bytes(),
                ),
                "/object" => {
                    let range = request
                        .headers
                        .lines()
                        .find_map(|line| line.strip_prefix("range: bytes="))
                        .map(str::to_owned);
                    seen.lock().unwrap().push(range.clone().unwrap_or_default());
                    match range.filter(|_| honor_range) {
                        Some(range) => {
                            let (start, end) = range.split_once('-').unwrap();
                            let start: usize = start.parse().unwrap();
                            let end: usize = end.parse().unwrap();
                            respond(&mut stream, "206 Partial Content", &ciphertext[start..=end]);
                        }
                        None => respond(&mut stream, "200 OK", &ciphertext),
                    }
                }
                other => panic!("unexpected request: {other}"),
            }
        }
    });
    (address, ranges)
}

fn encrypted_fixture(len: usize) -> (Vec<u8>, Vec<u8>) {
    let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
    let mut ciphertext = plaintext.clone();
    crypt(&mut ciphertext, MNEMONIC, &[0u8; 12], &INDEX);
    (plaintext, ciphertext)
}

#[test]
fn download_file_range_requests_only_the_enclosing_aes_blocks() {
    let (plaintext, ciphertext) = encrypted_fixture(1000);
    let (address, ranges) = spawn_download_server(ciphertext, plaintext.len(), true);
    let session = session(address);
    let client = InternxtNativeClient::new(&session.drive_api_url, session.active_token()).unwrap();

    // Unaligned start: the request begins at the 16-byte block boundary.
    let read = client
        .download_file_range(&session, "file", 21, 40)
        .unwrap();
    assert_eq!(read, plaintext[21..61]);
    // Aligned start, length clamped to the end of the file.
    let read = client
        .download_file_range(&session, "file", 992, 100)
        .unwrap();
    assert_eq!(read, plaintext[992..]);
    // Zero-length and end-of-file reads need no shard request.
    assert!(client
        .download_file_range(&session, "file", 1000, 10)
        .unwrap()
        .is_empty());
    assert!(client
        .download_file_range(&session, "file", 5, 0)
        .unwrap()
        .is_empty());
    assert!(client
        .download_file_range(&session, "file", 1001, 1)
        .is_err());

    assert_eq!(*ranges.lock().unwrap(), vec!["16-60", "992-999"]);
}

#[test]
fn download_file_range_falls_back_when_the_shard_ignores_range() {
    let (plaintext, ciphertext) = encrypted_fixture(4096 + 5);
    let (address, ranges) = spawn_download_server(ciphertext, plaintext.len(), false);
    let session = session(address);
    let client = InternxtNativeClient::new(&session.drive_api_url, session.active_token()).unwrap();

    let read = client
        .download_file_range(&session, "file", 3001, 1100)
        .unwrap();
    assert_eq!(read, plaintext[3001..4101]);
    assert_eq!(*ranges.lock().unwrap(), vec!["2992-4100"]);
}

#[derive(Default)]
struct UpdateLog {
    uploaded: Vec<u8>,
    finished: Value,
    created: Value,
    trashed: Vec<Value>,
    renamed: Option<(String, Value)>,
}

/// Minimal gateway for upload-beside-then-swap: the original `file` has no
/// extension (`type: null`), the replacement is listed under whatever name
/// the client created it with, then the original is trashed and the
/// replacement renamed.
fn spawn_update_server(fail_upload: bool) -> (SocketAddr, Arc<Mutex<UpdateLog>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(UpdateLog::default()));
    let shared = Arc::clone(&log);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let request = read_request(&mut stream);
            let mut log = shared.lock().unwrap();
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/files/file/meta") => respond(
                    &mut stream,
                    "200 OK",
                    br#"{"folderUuid":"folder","plainName":"report","type":null,"size":"3"}"#,
                ),
                (_, p) if p.contains("/files/start") => respond(
                    &mut stream,
                    "200 OK",
                    format!(r#"{{"uploads":[{{"uuid":"shard","url":"http://{address}/part"}}]}}"#)
                        .as_bytes(),
                ),
                ("PUT", "/part") if fail_upload => respond(&mut stream, "403 Forbidden", b"denied"),
                ("PUT", "/part") => {
                    log.uploaded = request.body;
                    respond(&mut stream, "200 OK", b"");
                }
                (_, p) if p.ends_with("/files/finish") => {
                    log.finished = serde_json::from_slice(&request.body).unwrap();
                    respond(&mut stream, "200 OK", br#"{"id":"network-file"}"#)
                }
                ("POST", "/files") => {
                    log.created = serde_json::from_slice(&request.body).unwrap();
                    respond(&mut stream, "200 OK", b"{}");
                }
                ("GET", p) if p.starts_with("/folders/content/folder/files") => {
                    let listing = if log.created.is_null() {
                        serde_json::json!({ "result": [] })
                    } else {
                        serde_json::json!({ "result": [{
                            "uuid": "replacement",
                            "plainName": log.created["plainName"],
                            "type": log.created["type"],
                            "size": "11",
                        }] })
                    };
                    respond(&mut stream, "200 OK", listing.to_string().as_bytes());
                }
                ("GET", p) if p.starts_with("/folders/content/folder/folders") => {
                    respond(&mut stream, "200 OK", br#"{"result":[]}"#)
                }
                ("POST", "/storage/trash/add") => {
                    log.trashed
                        .push(serde_json::from_slice(&request.body).unwrap());
                    respond(&mut stream, "200 OK", b"{}");
                }
                ("PUT", "/files/replacement/meta") => {
                    log.renamed = Some((
                        "replacement".into(),
                        serde_json::from_slice(&request.body).unwrap(),
                    ));
                    respond(&mut stream, "200 OK", b"{}");
                }
                (method, path) => panic!("unexpected request: {method} {path}"),
            }
        }
    });
    (address, log)
}

#[test]
fn update_file_from_reader_uploads_beside_then_swaps_keeping_no_extension() {
    let (address, log) = spawn_update_server(false);
    let session = session(address);
    let client = InternxtNativeClient::new(&session.drive_api_url, session.active_token()).unwrap();
    let replacement = b"new content".to_vec();
    client
        .update_file_from_reader(
            &session,
            "file",
            std::io::Cursor::new(replacement.clone()),
            replacement.len() as u64,
        )
        .unwrap();

    let log = log.lock().unwrap();
    let temporary = log.created["plainName"].as_str().unwrap();
    assert!(temporary.starts_with(".crispsorter-update-"), "{temporary}");
    assert_eq!(log.created["type"], "", "null type means no extension");
    let index: [u8; 32] = hex::decode(log.finished["index"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut decrypted = log.uploaded.clone();
    crypt(&mut decrypted, MNEMONIC, &[0u8; 12], &index);
    assert_eq!(decrypted, replacement);
    assert_eq!(log.trashed.len(), 1);
    assert_eq!(log.trashed[0]["items"][0]["uuid"], "file");
    let (uuid, body) = log.renamed.clone().expect("replacement was renamed");
    assert_eq!(uuid, "replacement");
    assert_eq!(body["plainName"], "report");
    assert_eq!(
        body["type"], "",
        "an extensionless file must not become report.file"
    );
}

#[test]
fn update_file_from_reader_leaves_the_original_when_the_upload_fails() {
    let (address, log) = spawn_update_server(true);
    let session = session(address);
    let client = InternxtNativeClient::new(&session.drive_api_url, session.active_token()).unwrap();
    let result = client.update_file_from_reader(
        &session,
        "file",
        std::io::Cursor::new(b"new content".to_vec()),
        11,
    );
    assert!(result.is_err());
    let log = log.lock().unwrap();
    assert!(log.trashed.is_empty(), "original must not be trashed");
    assert!(log.renamed.is_none());
}
