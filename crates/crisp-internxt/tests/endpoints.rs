use crisp_internxt::{InternxtNativeClient, InternxtSession};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn request_path(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&bytes)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned()
}

fn response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}",
        body.len(), body
    )
    .unwrap();
}

fn response_status(stream: &mut TcpStream, status: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}

#[test]
fn drive_and_auth_endpoints_are_exercised_against_http_harness() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut paths = Vec::new();
        for _ in 0..8 {
            let (mut stream, _) = listener.accept().unwrap();
            let path = request_path(&mut stream);
            if path.starts_with("/folders/content/root/folders") {
                response(
                    &mut stream,
                    r#"{"result":[{"plainName":"Docs","uuid":"dir"}]}"#,
                );
            } else if path.starts_with("/folders/content/root/files") {
                response(
                    &mut stream,
                    r#"{"result":[{"plainName":"note","type":"txt","uuid":"file","size":"4","modificationTime":"2024-01-02T03:04:05Z"}]}"#,
                );
            } else if path == "/folders" {
                response(&mut stream, r#"{"uuid":"new-folder"}"#);
            } else if path == "/storage/trash/add"
                || path == "/files/file/meta"
                || path == "/files/file"
            {
                response(&mut stream, "{}");
            } else if path == "/users/refresh" {
                response(
                    &mut stream,
                    r#"{"token":"refreshed","newToken":"refreshed-new"}"#,
                );
            } else if path.starts_with("/storage/trash/paginated") {
                response(&mut stream, r#"{"result":[]}"#);
            } else {
                panic!("unexpected endpoint: {path}");
            }
            paths.push(path);
        }
        paths
    });

    let base = format!("http://{address}");
    let session = InternxtSession {
        drive_api_url: base.clone(),
        network_url: base.clone(),
        email: "test@example.invalid".into(),
        token: "token".into(),
        new_token: "new-token".into(),
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        user_id: "user".into(),
        root_folder_id: "root".into(),
        bridge_user: "bridge".into(),
        bucket_id: "00".repeat(12),
    };
    let client = InternxtNativeClient::new(&base, "token").unwrap();
    let items = client.list_folder("root").unwrap();
    assert_eq!(items[1].name, "note.txt");
    assert_eq!(
        items[1].modified_at.as_deref(),
        Some("2024-01-02T03:04:05Z")
    );
    assert_eq!(client.create_folder("root", "New").unwrap(), "new-folder");
    client.trash("file", "file").unwrap();
    client.move_file("file", "dir").unwrap();
    client.rename_file("file", "renamed", "txt").unwrap();
    assert_eq!(
        client.refresh_session(&session).unwrap().new_token,
        "refreshed-new"
    );
    assert!(client.list_trash(Some("files"), 10).unwrap().is_empty());
    let paths = server.join().unwrap();
    assert!(paths.iter().any(|p| p == "/users/refresh"));
    assert!(paths.iter().any(|p| p == "/storage/trash/add"));
}

#[test]
fn expired_bearer_token_refreshes_and_retries_once() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for attempt in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let path = request_path(&mut stream);
            match attempt {
                0 => {
                    assert!(path.starts_with("/folders/content/root/folders"));
                    response_status(&mut stream, "401 Unauthorized", "unauthorized");
                }
                1 => {
                    assert_eq!(path, "/users/refresh");
                    response(
                        &mut stream,
                        r#"{"token":"refreshed","newToken":"refreshed-new"}"#,
                    );
                }
                2 => {
                    assert!(path.starts_with("/folders/content/root/folders"));
                    response(
                        &mut stream,
                        r#"{"result":[{"plainName":"Recovered","uuid":"dir"}]}"#,
                    );
                }
                _ => {
                    assert!(path.starts_with("/folders/content/root/files"));
                    response(&mut stream, r#"{"result":[]}"#);
                }
            }
        }
    });
    let base = format!("http://{address}");
    let mut session = InternxtSession {
        drive_api_url: base.clone(),
        network_url: base.clone(),
        email: "test@example.invalid".into(),
        token: "token".into(),
        new_token: "new-token".into(),
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        user_id: "user".into(),
        root_folder_id: "root".into(),
        bridge_user: "bridge".into(),
        bucket_id: "00".repeat(12),
    };
    let mut client = InternxtNativeClient::new(&base, "new-token").unwrap();
    let recovered = client
        .with_auto_refresh(&mut session, |client, _| client.list_folder("root"))
        .unwrap();
    assert_eq!(recovered[0].name, "Recovered");
    assert_eq!(session.new_token, "refreshed-new");
    server.join().unwrap();
}

#[test]
fn trash_listing_keeps_file_extension_and_exact_uuid() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let path = request_path(&mut stream);
        assert!(path.starts_with("/storage/trash/paginated?"));
        assert!(path.contains("limit=50"));
        let body = r#"{"result":[{"uuid":"deleted-object","plainName":"report","type":"pdf","size":42}]}"#;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let client = InternxtNativeClient::new(format!("http://{address}"), "fixture-token").unwrap();
    let items = client.list_trash(Some("files"), 50).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].uuid, "deleted-object");
    assert_eq!(items[0].name, "report.pdf");
    assert!(!items[0].is_dir);
    server.join().unwrap();
}

#[test]
fn trash_listing_all_kinds_preserves_folders_and_extensionless_files() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for (kind, body) in [
            ("files", r#"{"result":[{"uuid":"empty-type","plainName":"README","type":""},{"uuid":"null-type","plainName":"LICENSE","type":null},{"uuid":"missing-type","name":"NOTICE"}]}"#),
            ("folders", r#"{"result":[{"uuid":"folder","plainName":"Docs","type":"pdf"}]}"#),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let path = request_path(&mut stream);
            assert!(path.starts_with("/storage/trash/paginated?"));
            assert!(path.contains(&format!("type={kind}")));
            assert!(path.contains("offset=0"));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    let client = InternxtNativeClient::new(format!("http://{address}"), "fixture-token").unwrap();
    let items = client.list_trash(None, 50).unwrap();
    assert_eq!(items.iter().map(|item| item.name.as_str()).collect::<Vec<_>>(),
        ["README", "LICENSE", "NOTICE", "Docs"]);
    assert_eq!(items.iter().map(|item| item.uuid.as_str()).collect::<Vec<_>>(),
        ["empty-type", "null-type", "missing-type", "folder"]);
    assert!(items[..3].iter().all(|item| !item.is_dir));
    assert!(items[3].is_dir);
    server.join().unwrap();
}

#[test]
fn trash_listing_preserves_full_names_and_ids_across_pages() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for (offset, body) in [
            (0, r#"{"result":[{"uuid":"first-report","plainName":"report","type":"pdf"},{"uuid":"readme","plainName":"README","type":""}]}"#),
            (2, r#"{"result":[{"uuid":"second-report","plainName":"report","type":"pdf"}]}"#),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let path = request_path(&mut stream);
            assert!(path.starts_with("/storage/trash/paginated?"));
            assert!(path.contains("type=files"));
            assert!(path.contains("limit=2"));
            assert!(path.contains(&format!("offset={offset}")));
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    let client = InternxtNativeClient::new(format!("http://{address}"), "fixture-token").unwrap();
    let items = client.list_trash(Some("files"), 2).unwrap();
    assert_eq!(items.iter().map(|item| item.name.as_str()).collect::<Vec<_>>(),
        ["report.pdf", "README", "report.pdf"]);
    assert_eq!(items.iter().map(|item| item.uuid.as_str()).collect::<Vec<_>>(),
        ["first-report", "readme", "second-report"]);
    assert!(items.iter().all(|item| !item.is_dir));
    server.join().unwrap();
}
