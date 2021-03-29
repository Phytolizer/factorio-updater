use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;

use futures_util::StreamExt;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::from_str;

use crate::Config;
use crate::Error;
use crate::Version;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const PACKAGE: &str = "core-linux64";
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
const PACKAGE: &str = "core-win64";
#[cfg(target_os = "macos")]
const PACKAGE: &str = "core-mac";

#[derive(Deserialize, Serialize)]
pub(crate) struct AllUpdates {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[serde(rename = "core-linux64")]
    updates: Updates,
    #[cfg(all(target_os = "windows", target_pointer_width = "64"))]
    #[serde(rename = "core-win64")]
    updates: Updates,
    #[cfg(target_os = "macos")]
    #[serde(rename = "core-mac")]
    updates: Updates,
}

struct AllUpdatesIterator<'u> {
    updates: &'u Vec<Update>,
    index: usize,
}

impl<'u> Iterator for AllUpdatesIterator<'u> {
    type Item = &'u Update;

    fn next(&mut self) -> Option<Self::Item> {
        self.index += 1;
        self.updates.get(self.index - 1)
    }
}

impl AllUpdates {
    fn iter(&self) -> AllUpdatesIterator {
        AllUpdatesIterator {
            updates: &self.updates.0,
            index: 0,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct Updates(Vec<Update>);

#[derive(Deserialize, Serialize)]
struct RawUpdate {
    from: Option<Version>,
    to: Option<Version>,
    stable: Option<Version>,
}

impl TryFrom<RawUpdate> for Update {
    type Error = String;

    fn try_from(value: RawUpdate) -> Result<Self, Self::Error> {
        if let Some(from) = value.from {
            Ok(Update::Update {
                from,
                to: value.to.ok_or("Failed to parse updates json!")?,
            })
        } else {
            Ok(Update::StableVersion(
                value.stable.ok_or("Failed to parse updates json!")?,
            ))
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(try_from = "RawUpdate")]
pub(crate) enum Update {
    Update { from: Version, to: Version },
    StableVersion(Version),
    None,
}

impl Default for Update {
    fn default() -> Self {
        Self::None
    }
}

pub(crate) async fn get_available_versions(
    client: &Client,
    config: &Config,
) -> Result<AllUpdates, Error> {
    Ok(from_str(
        client
            .get("https://updater.factorio.com/get-available-versions")
            .query(&[
                ("username", config.username.as_str()),
                ("token", config.token.as_str()),
            ])
            .send()
            .await?
            .text()
            .await?
            .as_str(),
    )
    .map_err(|e| Error::Json("update", e))?)
}

pub(crate) struct UpdateStrategy(Vec<Update>);

struct UpdateStrategyIterator<'u> {
    strategy: &'u mut Vec<Update>,
    index: usize,
}

impl<'u> Iterator for UpdateStrategyIterator<'u> {
    type Item = Update;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(update) = self.strategy.get_mut(self.index) {
            let mut nothing = Update::default();
            mem::swap(&mut nothing, update);
            self.index += 1;
            Some(nothing)
        } else {
            None
        }
    }
}

impl UpdateStrategy {
    fn iter_mut<'u>(&'u mut self) -> UpdateStrategyIterator<'u> {
        UpdateStrategyIterator {
            strategy: &mut self.0,
            index: 0,
        }
    }
}

pub(crate) fn compute_update_strategy<'u>(
    current_version: Version,
    stable_version: Version,
    updates: AllUpdates,
) -> Result<UpdateStrategy, Error> {
    let mut update_strategy = UpdateStrategy(vec![]);
    let mut start = current_version;
    'strategizing: loop {
        let old_start = start.clone();
        for update in updates.iter() {
            if let Update::Update { from, to } = update {
                if from == &start {
                    println!("Found update from {} to {}", start, to);
                    start = to.clone();
                    update_strategy.0.push(update.clone());
                    if start == stable_version {
                        break 'strategizing;
                    }
                }
            }
        }
        if start == old_start {
            return Err(Error::CannotUpdateFrom(start.clone()));
        }
    }
    Ok(update_strategy)
}

#[derive(Serialize, Deserialize)]
struct DownloadLink(Vec<String>);

pub(crate) async fn execute_update_strategy(
    mut update_strategy: UpdateStrategy,
    config: &Config,
    client: &Client,
) -> Result<(), Error> {
    let temp_dir = tempfile::TempDir::new()?;
    for update in update_strategy.iter_mut() {
        if let Update::Update { from, to } = update {
            let payload = [
                ("username", config.username.as_str()),
                ("token", config.token.as_str()),
                ("package", PACKAGE),
                ("from", from.as_str()),
                ("to", to.as_str()),
            ];
            let response = client
                .get("https://updater.factorio.com/get-download-link")
                .query(&payload)
                .send()
                .await?
                .text()
                .await?;
            let mut link: DownloadLink =
                from_str(response.as_str()).map_err(|e| Error::Json("download link", e))?;
            let link = link.0.swap_remove(0);
            let download = client.get(link.as_str()).send().await?;
            let content_disposition = download
                .headers()
                .get("content-disposition")
                .unwrap()
                .to_str()
                .unwrap();
            let regex = Regex::new(
                format!(
                    r"attachment; filename=({}-{}-{}-update.zip)",
                    PACKAGE,
                    from.as_str(),
                    to.as_str()
                )
                .as_str(),
            )
            .unwrap();
            let out_path = temp_dir.path().join(
                regex
                    .captures(content_disposition)
                    .unwrap()
                    .get(1)
                    .unwrap()
                    .as_str()
                    .to_owned(),
            );
            let mut out_file = File::create(out_path.as_path())?;
            let file_type = download
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();

            let progress_bar = ProgressBar::new(
                download
                    .headers()
                    .get("content-length")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap(),
            );
            let mut stream = download.bytes_stream();
            progress_bar.set_message(
                format!(
                    "Downloading update from {} to {}",
                    from.as_str(),
                    to.as_str()
                )
                .as_str(),
            );
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .progress_chars("##.")
                    .template("{msg} {wide_bar} [{bytes_per_sec}]"),
            );
            let mut nbytes = 0;
            while let Some(bytes) = stream.next().await {
                let mut bytes = bytes?;
                nbytes += bytes.len();
                progress_bar.set_position(nbytes as u64);
                out_file.write_all(&mut bytes)?;
            }
            progress_bar.finish_with_message("Download successful.");

            let out_path = convert_to_zip(file_type.as_str(), &out_path)?;
            apply_update(temp_dir.path(), &out_path, config)?;
        }
    }

    Ok(())
}

fn convert_to_zip(file_type: &str, file: &Path) -> Result<PathBuf, Error> {
    match file_type {
        "application/zip" => return Ok(file.to_owned()),
        _ => {
            dbg!(file);
            exit(1);
        }
    }
}

fn apply_update(dir: &Path, zip: &Path, config: &Config) -> Result<(), Error> {
    let status = Command::new(config.factorio.as_path())
        .args(&["--apply-update", zip.to_str().unwrap()])
        .current_dir(dir)
        .spawn()?
        .wait()?;
    if !status.success() {
        Err(Error::UpdateFailed)
    } else {
        Ok(())
    }
}
