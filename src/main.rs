extern crate clap;
#[macro_use]
extern crate log;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate simple_logger;
extern crate tempfile;

use reqwest::header::USER_AGENT;
use reqwest::StatusCode;
use std::error;
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

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

fn main() {
    // Initialize, parse & verify flags.
    simple_logger::init_with_level(log::Level::Info).expect("Could not initialize logging");
    let flags = clap::App::new("rgdcd")
        .version("0.1")
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
    let state_path = Path::new(flags.value_of_os("state").unwrap());
    let cfg: Config = {
        let config_filename = flags.value_of_os("config").unwrap();
        let config_file = File::open(config_filename).expect("Could not open config file");
        serde_yaml::from_reader(config_file).expect("Could not parse config file")
    };
    let mut state: State = match File::open(state_path) {
        Ok(state_file) => serde_yaml::from_reader(state_file).expect("Could not parse state file"),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => State { addr: None },
        Err(err) => panic!("Could not read state file: {}", err),
    };

    // Main loop: check IP every now and then, update if necessary.
    info!("Starting: will check & update IP every 60s");
    let client = reqwest::blocking::Client::new();
    let mut last_check_time = Instant::now() - Duration::from_secs(60);
    let mut goog_addr = state.addr; // goog_addr stores our conception of what Google thinks our IP is.
    loop {
        // Wait until the next check.
        let next_check_time = last_check_time + Duration::from_secs(60);
        let now = Instant::now();
        if now < next_check_time {
            thread::sleep(next_check_time - now);
        }
        last_check_time = next_check_time;

        // Figure out what our current IP is.
        let current_addr = match current_address(&client) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Could not get current IP address: {}", e);
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
            if let Err(err) = update_address(&cfg, &client, current_addr) {
                error!("Could not update IP address: {}", err);
                continue;
            }
            goog_addr = Some(current_addr);
        }

        // Update state on disk if it differs.
        if Some(current_addr) != state.addr {
            let mut new_state = state.clone();
            new_state.addr = Some(current_addr);
            if let Err(err) = update_state(state_path, &new_state) {
                error!("Could not write state file: {}", err);
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

fn current_address(client: &reqwest::blocking::Client) -> Result<Ipv4Addr, Box<dyn error::Error>> {
    let resp = client
        .get("https://domains.google.com/checkip")
        .header(USER_AGENT, "rgdcd 1.0")
        .send()?;
    if resp.status() != StatusCode::OK {
        return Err(format!("unexpected status code: {}", resp.status()).into());
    }
    Ok(resp.text()?.parse()?)
}

fn update_address(
    cfg: &Config,
    client: &reqwest::blocking::Client,
    addr: Ipv4Addr,
) -> Result<(), Box<dyn error::Error>> {
    let resp = client
        .post("https://domains.google.com/nic/update")
        .header(USER_AGENT, "rgdcd 1.0")
        .basic_auth(&cfg.username, Some(&cfg.password))
        .query(&[("hostname", &cfg.hostname), ("myip", &addr.to_string())])
        .body("")
        .send()?;
    let status = resp.status();
    let txt = resp.text()?;
    if txt.starts_with("good") {
        return Ok(());
    }
    Err(format!("update request got error: {} ({})", txt, status).into())
}

fn update_state(state_path: &Path, state: &State) -> Result<(), Box<dyn error::Error>> {
    let dir = state_path.parent().ok_or_else(|| {
        format!(
            "could not determine parent directory of {}",
            state_path.display()
        )
    })?;
    let temp_file = NamedTempFile::new_in(dir)?;
    serde_yaml::to_writer(&temp_file, state)?;
    temp_file.persist(state_path)?;
    Ok(())
}
