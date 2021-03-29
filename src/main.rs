use std::cmp::PartialOrd;
use std::fmt::Display;
use std::fs::create_dir;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::process::exit;
use std::process::Command;
use std::{cmp::Ordering, fs::create_dir_all};

use dirs::cache_dir;
use dirs::config_dir;
use itertools::EitherOrBoth;
use itertools::Itertools;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json as json;
use tokio::runtime;
use update::compute_update_strategy;
use update::execute_update_strategy;
use update::get_available_versions;
use update::AllUpdates;
use EitherOrBoth::Both;
use EitherOrBoth::Left;
use EitherOrBoth::Right;

#[derive(Deserialize, Serialize)]
struct Config {
    username: String,
    token: String,
    factorio: PathBuf,
}

mod update;

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
struct Version(String);

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "version {}", self.0)
    }
}

impl Version {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Deserialize, Serialize)]
struct Versions {
    alpha: Version,
    demo: Version,
    headless: Version,
}

#[derive(Deserialize, Serialize)]
struct LatestRelease {
    experimental: Versions,
    stable: Versions,
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        for pair in self.0.split('.').zip_longest(other.0.split('.')) {
            match pair {
                Both(s, o) => {
                    if s != o {
                        return s
                            .parse::<usize>()
                            .unwrap()
                            .cmp(&o.parse::<usize>().unwrap());
                    }
                }
                Left(s) => {
                    if s > "0" {
                        return Ordering::Greater;
                    }
                }
                Right(o) => {
                    if o > "0" {
                        return Ordering::Less;
                    }
                }
            }
        }
        Ordering::Equal
    }
}

fn cache_file() -> Result<PathBuf, Error> {
    cache_dir()
        .ok_or(Error::NoCacheDir)
        .and_then(|cd| {
            if !cd.exists() {
                println!("Creating {}", cd.to_string_lossy());
                create_dir(cd.as_path())?;
            }
            Ok(cd)
        })
        .and_then(|cd| {
            let p = cd.join(env!("CARGO_PKG_NAME"));
            if !p.exists() {
                println!("Creating cache directory in {}", p.to_string_lossy());
                create_dir(p.as_path())?;
            }
            Ok(p.join("versions.json"))
        })
}

fn config_file() -> Result<PathBuf, Error> {
    config_dir().ok_or(Error::NoConfigDir).and_then(|p| {
        if !p.exists() {
            create_dir(&p)?;
        }
        let p = p.join(env!("CARGO_PKG_NAME"));
        if !p.exists() {
            create_dir(&p)?;
        }
        Ok(p.join("config.toml"))
    })
}

async fn update(
    client: &Client,
    config: &Config,
    current_version: Version,
    updates: AllUpdates,
    new_version: Version,
) -> Result<(), Error> {
    println!("Computing update strategy...");
    let update_strategy = compute_update_strategy(current_version, new_version, updates)?;
    execute_update_strategy(update_strategy, config, client).await
}

fn main() {
    let runtime = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    match runtime.block_on(run()) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

async fn run() -> Result<(), Error> {
    println!("Checking for cached version");
    let mut cached_version = read_or_reset()?;
    println!("Looking for a config file.");
    let mut s = String::new();
    File::open(config_file()?).map_err(|e| {
        println!(
            "Couldn't find a config file at {}. Please create one there.",
            config_file().unwrap().to_string_lossy()
        );
        println!("(a config file is necessary because this program requires your username and a valid token.)");
        e
    })?.read_to_string(&mut s)?;
    let config: Config =
        toml::from_str(s.as_str()).map_err(|e| Error::Toml("config file as TOML", e))?;
    let client = Client::builder().use_native_tls().build()?;
    println!("Fetching latest version.");
    let new_version = fetch_new_version(&client).await?;
    if cached_version.0.is_empty() {
        println!("No cache found. Running your Factorio binary to get it.");
        let version_output = Command::new(&config.factorio).arg("--version").output()?;
        let version = Version(
            String::from_utf8(version_output.stdout)
                .expect("Factorio produced invalid output")
                .split_whitespace()
                .skip(1)
                .next()
                .unwrap()
                .to_owned(),
        );
        cached_version = version;
    }
    println!("Factorio is {}.", cached_version);
    println!("Updated is {}.", new_version.stable.alpha);
    if new_version.stable.alpha > cached_version {
        let updates = get_available_versions(&client, &config).await?;
        println!("Applying updates...");
        update(
            &client,
            &config,
            cached_version,
            updates,
            new_version.stable.alpha.clone(),
        )
        .await?;
    }
    File::create(config_file()?)?.write(
        toml::to_string_pretty(&config)
            .map_err(|e| {
                eprintln!("The impossible happened: {}", e);
                exit(1);
            })
            .unwrap()
            .as_bytes(),
    )?;
    cache(new_version.stable.alpha)?;

    Ok(())
}

fn cache(new_version: Version) -> Result<(), Error> {
    File::create(cache_file()?)?
        .write_all(toml::to_string_pretty(&new_version).unwrap().as_bytes())
        .map_err(Into::into)
}

fn read_or_reset() -> Result<Version, Error> {
    let mut s = String::new();
    File::open(cache_file()?)
        .map_err(Error::Io)
        .or_else(|e| {
            if let Error::Io(_) = e {
                create_dir_all(cache_dir().unwrap())?;
                File::create(cache_file()?)?;
                Ok(File::open(cache_file()?).unwrap())
            } else {
                Err(e)
            }
        })?
        .read_to_string(&mut s)?;
    if s.trim().is_empty() {
        return Ok(Version(s.trim().to_owned()));
    }
    toml::from_str(s.as_str()).map_err(|e| Error::Toml("cached version as TOML", e))
}

async fn fetch_new_version(client: &Client) -> Result<LatestRelease, Error> {
    Ok(json::from_str(
        client
            .get("https://www.factorio.com/api/latest-releases")
            .send()
            .await?
            .text()
            .await?
            .as_str(),
    )
    .map_err(|e| Error::Json("latest releases as JSON", e))?)
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("no cache directory available")]
    NoCacheDir,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("parsing {0}: {1}")]
    Toml(&'static str, toml::de::Error),
    #[error("parsing {0}: {1}")]
    Json(&'static str, json::Error),
    #[error("no config directory available")]
    NoConfigDir,
    #[error("the Factorio update failed")]
    UpdateFailed,
    #[error("cannot update from {0}")]
    CannotUpdateFrom(Version),
}
