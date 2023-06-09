use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::Parser;
use exe::PE;
use rayon::prelude::*;
use ureq::Error;

const RP: &str = "./report";
static COUNTER: AtomicUsize = AtomicUsize::new(0);
#[derive(Parser)]
struct Cli {
    malware_folder_path: String,
    api_key_file_path: String,
}

fn rename<P: AsRef<Path>>(base: P, from_name: &str, to_name: &str) {
    let src = base.as_ref().join(from_name);
    let target = base.as_ref().join(to_name);
    std::fs::rename(src, target).unwrap();
}

fn main() -> anyhow::Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(10)
        .build_global()?;
    let cli = Cli::parse();
    let malware_folder_path = Path::new(&cli.malware_folder_path);

    std::fs::create_dir(RP).ok();

    let mut keys = {
        let apikeys_file = std::fs::File::open(&cli.api_key_file_path)?;
        BufReader::new(apikeys_file)
            .lines()
            .filter_map(|l| l.ok())
            .collect::<VecDeque<String>>()
    };

    let current_key = keys.pop_front();

    if let Some(key) = current_key.as_ref() {
        keys.push_back(key.clone());
    }

    let mut file = std::fs::File::options()
        .write(true)
        .truncate(true)
        .open(cli.api_key_file_path)?;
    for key in keys {
        file.write_all(format!("{key}\n").as_bytes())?;
    }

    std::fs::read_dir(malware_folder_path)?
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|e| e.as_ref().ok())
        .filter(|e| e.metadata().map(|f| f.is_file()).unwrap_or(false))
        .filter(|e| !e.file_name().into_string().unwrap().ends_with("_labelled"))
        .filter_map(|e| {
            let file_name = e.file_name().into_string().unwrap();
            let mut buf = Vec::new();
            std::fs::File::open(e.path())
                .ok()?
                .read_to_end(&mut buf)
                .ok()?;
            let md5 = format!("{:x}", md5::compute(&buf));
            if exe::pe::VecPE::from_disk_data(&buf)
                .get_valid_nt_headers()
                .is_ok()
            {
                Some((file_name, md5))
            } else {
                rename(
                    malware_folder_path,
                    &file_name,
                    &[&file_name, "notpe", "labelled"].join("_"),
                );
                None
            }
        })
        .any(|(file_name, hash)| {
            let key = if let Some(key) = &current_key {
                key.clone()
            } else {
                println!("no key");
                return true;
            };
            let res_r = ureq::get(&format!("https://www.virustotal.com/api/v3/files/{hash}"))
                .set("x-apikey", &key)
                .call();
            match res_r {
                Ok(res) => {
                    if let Ok(json) = res.into_json::<serde_json::Value>() {
                        if let Ok(mut file) = std::fs::File::create(format!("{RP}/{file_name}")) {
                            file.write_all(&serde_json::to_vec(&json).unwrap()).ok();
                        }
                        if let Some(malware_type) = json["data"]["attributes"]
                            ["popular_threat_classification"]["suggested_threat_label"]
                            .as_str()
                        {
                            let malware_type = malware_type.replace("/", ".");
                            println!(
                                "{}: {hash} is {malware_type}",
                                COUNTER.fetch_add(1, Ordering::Relaxed)
                            );
                            rename(
                                malware_folder_path,
                                &file_name,
                                &[file_name.as_str(), &malware_type, "labelled"].join("_"),
                            );
                        } else {
                            println!(
                                "{}: {hash} is no label",
                                COUNTER.fetch_add(1, Ordering::Relaxed)
                            );
                            rename(
                                malware_folder_path,
                                &file_name,
                                &[&file_name, "nolabel", "labelled"].join("_"),
                            );
                        }
                    }
                    return false;
                }
                Err(Error::Status(429, _r)) => {
                    println!("Error 429 {:?}", std::time::SystemTime::now());
                }
                Err(Error::Status(401, _r)) => {
                    println!(
                        "Error 401 maybe user is banned {:?}",
                        std::time::SystemTime::now()
                    );
                }
                Err(Error::Status(n, _)) => {
                    rename(
                        malware_folder_path,
                        &file_name,
                        &[
                            &file_name,
                            n.to_string().as_str(),
                            "or_undetected",
                            "labelled",
                        ]
                        .join("_"),
                    );
                }
                Err(e) => {
                    println!("Error {e}");
                }
            };

            true
        });
    println!("Change ip and rerun!");
    Ok(())
}
