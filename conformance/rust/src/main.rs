//! Executes real package APIs against the language-neutral fixture corpus.
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use crisp_filen as filen;
use crisp_internxt as internxt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn text<'a>(case: &'a Value, key: &str) -> Result<&'a str> {
    case[key].as_str().with_context(|| format!("missing {key}"))
}
fn bytes(case: &Value, key: &str) -> Result<Vec<u8>> {
    hex::decode(text(case, key)?).map_err(Into::into)
}
fn pattern(size: usize) -> Vec<u8> { (0..size).map(|i| ((i * 17 + 23) % 251) as u8).collect() }
fn summary(data: &[u8]) -> Value { json!({"length": data.len(), "sha256": hex::encode(Sha256::digest(data))}) }
fn encrypted(case: &Value, root: &Path) -> Result<Vec<u8>> {
    if let Some(relative) = case["encrypted_file"].as_str() {
        anyhow::ensure!(!relative.contains("..") && !Path::new(relative).is_absolute(), "fixture path");
        Ok(fs::read(root.join(relative))?)
    } else { Ok(STANDARD.decode(text(case, "encrypted")?)?) }
}
fn run(case: &Value, root: &Path, exports: &mut Vec<Value>) -> Result<Value> {
    let id = text(case, "id")?;
    let op = text(case, "op")?;
    let value = match op {
        "filen.mock.list" => {
            let base = text(case,"base_url")?;
            let session = filen::FilenSession {
                gateway_url:base.to_owned(),ingest_url:base.to_owned(),egest_url:base.to_owned(),
                email:"synthetic@example.invalid".into(),api_key:"synthetic-test-token".into(),
                auth_version:filen::AuthVersion::V2,file_encryption_version:2,metadata_encryption_version:2,
                root_folder_uuid:"root".into(),master_keys:vec![b"conformance-only-master-key".to_vec()],
                dek:None,kek:None,private_key:None,hmac_key:None,
            };
            let client = filen::FilenNativeClient::from_session(&session)?;
            let mut items = Vec::new();
            for _ in 0..case["repeat"].as_u64().unwrap_or(1) {items = client.list_folder_cached("root")?;}
            let mut normalized:Vec<_> = items.iter().map(|i|json!({"uuid":i.uuid,"name":i.name,"is_dir":i.is_dir,"size":i.size})).collect();
            normalized.sort_by(|a,b|a["uuid"].as_str().cmp(&b["uuid"].as_str()));
            json!(normalized)
        }
        "internxt.mock.list" | "internxt.mock.mutate" => {
            let client = internxt::InternxtNativeClient::new(text(case,"base_url")?,"synthetic-test-token")?;
            if op == "internxt.mock.list" {
                let mut items = Vec::new();
                for _ in 0..case["repeat"].as_u64().unwrap_or(1) {items = client.list_folder_cached("root")?;}
                let mut normalized:Vec<_> = items.iter().map(|i|json!({"uuid":i.uuid,"name":i.name,"is_dir":i.is_dir,"size":i.size})).collect();
                normalized.sort_by(|a,b|a["uuid"].as_str().cmp(&b["uuid"].as_str()));
                json!(normalized)
            } else {
                match text(case,"action")? {
                    "create" => json!(client.create_folder("root","新規 Grüße")?),
                    "rename" => {client.rename_file("file","新規 Grüße","txt")?;json!(true)},
                    "move" => {client.move_file("file","destination")?;json!(true)},
                    "trash" => {client.trash("file","file")?;json!(true)},
                    _ => return Err(anyhow!("unknown mutation")),
                }
            }
        }
        "filen.login" => {
            let (raw, password) = filen::pbkdf2_login(text(case,"password")?,text(case,"salt")?);
            let raw = hex::encode(raw);
            if case["version"] == 2 {json!({"masterKey": &raw[..64], "password": password})}
            else {json!({"masterKey": raw, "password": raw})}
        }
        "filen.metadata.encrypt" => json!(filen::v2_encrypt_metadata(text(case,"text")?,text(case,"key")?.as_bytes(),*b"aaaaaaaaaaaa")?),
        "filen.metadata.decrypt" => json!(filen::v2_decrypt_metadata(text(case,"encrypted")?,text(case,"key")?.as_bytes())?),
        "filen.chunk.encrypt.reject" => {
            let key:[u8;32]=bytes(case,"key")?.try_into().map_err(|_|anyhow!("key length"))?;
            json!(STANDARD.encode(filen::encrypt_file_chunk(b"hello",&key,*b"aaaaaaaaaaaa")?))
        }
        "filen.chunk" | "filen.chunk.decrypt" => {
            let key: [u8;32] = bytes(case,"key")?.try_into().map_err(|_|anyhow!("key length"))?;
            let raw = encrypted(case,root)?;
            let plain = filen::decrypt_file_chunk(&raw,&key)?;
            if case["export"] == true {
                let source = pattern(case["size"].as_u64().context("size")? as usize);
                let sealed = filen::encrypt_file_chunk(&source,&key,*b"aaaaaaaaaaaa")?;
                anyhow::ensure!(sealed == raw, "independent encryption vector differs");
                exports.push(json!({"id":id,"op":"filen.chunk.decrypt","encrypted":STANDARD.encode(sealed),"key":case["key"],"expected":case["expected"]}));
            }
            summary(&plain)
        }
        "internxt.password" => json!(internxt::password_hash(text(case,"password")?,text(case,"salt")?)?),
        "internxt.text.decrypt" => json!(String::from_utf8(internxt::decrypt_text(text(case,"encrypted")?,text(case,"key")?)?)?),
        "internxt.text.roundtrip" => {
            let plain = text(case,"text")?;
            let sealed = internxt::encrypt_text(plain.as_bytes(),text(case,"key")?)?;
            let result = String::from_utf8(internxt::decrypt_text(&sealed,text(case,"key")?)?)?;
            exports.push(json!({"id":id,"op":"internxt.text.decrypt","encrypted":sealed,"key":case["key"],"expected":case["expected"]}));
            json!(result)
        }
        "internxt.key" | "internxt.ctr" | "internxt.range" | "internxt.ctr.decrypt" | "internxt.stream" => {
            let bucket: [u8;12] = bytes(case,"bucket")?.try_into().map_err(|_|anyhow!("bucket length"))?;
            let index: [u8;32] = bytes(case,"index")?.try_into().map_err(|_|anyhow!("index length"))?;
            let mnemonic = text(case,"mnemonic")?;
            if op == "internxt.key" { json!(hex::encode(internxt::file_key(mnemonic,&bucket,&index))) }
            else {
                let mut plain = encrypted(case,root)?;
                let offset = case.get("offset").map(|x|x.as_u64().context("negative offset")).transpose()?.unwrap_or(0);
                if op == "internxt.stream" {
                    let mut cursor=0;
                    for length in case["chunks"].as_array().context("chunks")? {
                        let end=cursor+length.as_u64().context("length")? as usize;
                        internxt::crypt_at(&mut plain[cursor..end],mnemonic,&bucket,&index,cursor as u64)?;
                        cursor=end;
                    }
                    anyhow::ensure!(cursor==plain.len(),"incomplete streaming fixture");
                } else {internxt::crypt_at(&mut plain,mnemonic,&bucket,&index,offset)?;}
                if case["export"] == true {
                    let source = pattern(case["size"].as_u64().context("size")? as usize);
                    let mut fixed = source.clone(); internxt::crypt(&mut fixed,mnemonic,&bucket,&index);
                    anyhow::ensure!(fixed == encrypted(case,root)?,"independent CTR vector differs");
                    let (new_index,sealed) = internxt::encrypt(&source,mnemonic,&bucket);
                    exports.push(json!({"id":id,"op":"internxt.ctr.decrypt","encrypted":STANDARD.encode(sealed),"index":hex::encode(new_index),"bucket":case["bucket"],"mnemonic":mnemonic,"expected":case["expected"]}));
                }
                summary(&plain)
            }
        }
        _ => return Err(anyhow!("unknown conformance operation")),
    };
    Ok(json!({"status":"ok","value":value}))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3,"probe <fixtures.json> <output.json>");
    let input: Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let cases = input["cases"].as_array().context("cases")?;
    let root = Path::new(&args[1]).parent().context("fixture root")?;
    let mut results = serde_json::Map::new(); let mut exports = Vec::new();
    // A panic is a distinct failure, never an accepted parse/crypto rejection.
    std::panic::set_hook(Box::new(|_|{}));
    for case in cases {
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||run(case,root,&mut exports))) {
            Ok(Ok(value))=>value, Ok(Err(_))=>json!({"status":"rejected"}), Err(_)=>json!({"status":"panicked"}),
        };
        results.insert(text(case,"id")?.to_owned(),result);
    }
    fs::write(&args[2],serde_json::to_vec(&json!({"schema":1,"engine":"rust","results":results,"exports":exports}))?)?;
    println!("Rust probe: {} cases, {} exports",cases.len(),exports.len());
    Ok(())
}
