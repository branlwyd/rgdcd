use anyhow::{anyhow, Result};
use log::{error, info};
use reqwest::{
    header::{HeaderMap, HeaderValue, USER_AGENT},
    StatusCode,
};
use serde_derive::{Deserialize, Serialize};
use std::{fs::File, io, net::Ipv4Addr, path::Path, time::Duration};
use tempfile::NamedTempFile;
use tokio::time::{self, MissedTickBehavior};

// TODO: asynchronize filesystem operations (including NamedTempFile).

#[derive(Deserialize)]
struct Config {
    hostname: String,
    username: String,
    password: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
    addr: Option<Ipv4Addr>,
}

#[tokio::main]
async fn main() {
    // Initialize, parse & verify flags.
    simple_logger::init_with_level(log::Level::Info).expect("Couldn't initialize logging");
    let flags = clap::App::new("rgdcd")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Brandon Pitman <bran@bran.land>")
        .about("Google Domains Dynamic DNS Client Daemon")
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .value_name("FILE")
                .help("The config file to use (read-only)")
                .required(true)
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("state")
                .long("state")
                .value_name("FILE")
                .help("The state file to use (read/write)")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    // Parse config & state files.
    // XXX: asynchronize?
    let state_path = Path::new(flags.value_of_os("state").unwrap());
    let cfg: Config = {
        let config_filename = flags.value_of_os("config").unwrap();
        let config_file = File::open(config_filename).expect("Couldn't open config file");
        serde_yaml::from_reader(config_file).expect("Couldn't parse config file")
    };
    let mut state: State = match File::open(state_path) {
        Ok(state_file) => serde_yaml::from_reader(state_file).expect("Couldn't parse state file"),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => State { addr: None },
        Err(err) => panic!("Couldn't read state file: {}", err),
    };

    // Build an HTTP client.
    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&format!("rgdcd {}", env!("CARGO_PKG_VERSION")))
            .expect("Couldn't create default HTTP headers"),
    );
    let client = reqwest::Client::builder()
        .default_headers(default_headers)
        .build()
        .expect("Couldn't create HTTP client");

    // Main loop: check IP every now and then, update if necessary.
    info!("Starting: will check & update IP every 60s");
    let mut interval = time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut goog_addr = state.addr; // goog_addr stores our conception of what Google thinks our IP is.
    loop {
        interval.tick().await;

        // Figure out what our current IP is.
        let current_addr = match current_address(&client).await {
            Ok(addr) => addr,
            Err(e) => {
                error!("Couldn't get current IP address: {}", e);
                continue;
            }
        };

        // Update IP in Google Domains if it differs.
        if Some(current_addr) != goog_addr {
            info!(
                "Detected new IP ({} -> {}), updating",
                fmt_optional_addr(&goog_addr),
                current_addr
            );
            if let Err(err) = update_address(&cfg, &client, current_addr).await {
                error!("Couldn't update IP address: {}", err);
                continue;
            }
            goog_addr = Some(current_addr);
        }

        // Update state on disk if it differs.
        if Some(current_addr) != state.addr {
            let mut new_state = state.clone();
            new_state.addr = Some(current_addr);
            if let Err(err) = update_state(state_path, &new_state).await {
                error!("Couldn't write state file: {}", err);
                continue;
            }
            state = new_state;
        }
    }
}

fn fmt_optional_addr(addr: &Option<Ipv4Addr>) -> String {
    match addr {
        None => "None".into(),
        Some(a) => a.to_string(),
    }
}

async fn current_address(client: &reqwest::Client) -> Result<Ipv4Addr> {
    let resp = client
        .get("https://domains.google.com/checkip")
        .send()
        .await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("unexpected status code: {}", resp.status()));
    }
    Ok(resp.text().await?.parse()?)
}

async fn update_address(cfg: &Config, client: &reqwest::Client, addr: Ipv4Addr) -> Result<()> {
    let resp = client
        .post("https://domains.google.com/nic/update")
        .basic_auth(&cfg.username, Some(&cfg.password))
        .query(&[("hostname", &cfg.hostname), ("myip", &addr.to_string())])
        .body("")
        .send()
        .await?;
    let status = resp.status();
    let txt = resp.text().await?;
    if txt.starts_with("good") {
        return Ok(());
    }
    Err(anyhow!("update request got error: {} ({})", txt, status))
}

async fn update_state(state_path: &Path, state: &State) -> Result<()> {
    let dir = state_path.parent().ok_or_else(|| {
        anyhow!(
            "couldn't determine parent directory of {}",
            state_path.display()
        )
    })?;
    let temp_file = NamedTempFile::new_in(dir)?;
    serde_yaml::to_writer(&temp_file, state)?;
    temp_file.persist(state_path)?;
    Ok(())
}
