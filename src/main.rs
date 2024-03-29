#![allow(clippy::single_component_path_imports)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use esp_idf_hal::peripheral;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use serde::{Deserialize, Serialize};

use embeddable_rest_server::{
    BodyType, CancelHandler, HandlerResult, HttpError, RequestHandler, Response, RestServer,
    SpawnedRestServer, Streamable,
};
use embedded_svc::{
    ipv4::{
        ClientConfiguration as IpClientConfiguration, Configuration as IpConfiguration,
        DHCPClientSettings,
    },
    wifi::{self, ClientConfiguration as WifiClientConfiguration},
};
use esp_idf_svc::netif::{EspNetif, NetifConfiguration, NetifStack};
use esp_idf_svc::wifi::{BlockingWifi, EspWifi, WifiDriver};

use esp_idf_svc::sntp;
use log::*;

use esp_idf_hal::peripherals::Peripherals;

use esp32_sdcard::*;

mod readdir;
use readdir::Files;

fn main() -> Result<()> {
    esp_idf_sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;

    let pins = SdPins {
        cmd: peripherals.pins.gpio15,
        clk: peripherals.pins.gpio14,
        d0: peripherals.pins.gpio2,
        d1: peripherals.pins.gpio4,
        d2: peripherals.pins.gpio12,
        d3: peripherals.pins.gpio13,
    };

    let sd = Arc::new(SdmmcCard::new(pins)?);
    let size = sd.size();
    let read_block_len = sd.read_block_len();
    info!(
        "card size: {} MB, read block size: {}",
        size / (1024 * 1024),
        read_block_len
    );
    let mounted = MountedFat::mount(sd, "/sd")?;
    let statistics = mounted.statistics();
    info!("{:?}", statistics);

    let _wifi = wifi(peripherals.modem)?;

    let _sntp = sntp::EspSntp::new_default()?;
    info!("SNTP initialized");

    let server = start_server().map_err(|err| anyhow!(format!("{:?}", err)))?;

    while !server.is_stopped() {
        thread::sleep(Duration::from_millis(100));
    }

    drop(mounted);

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct WifiConfig {
    ssid: String,
    pw: String,
}

struct ReadableFile {
    file: File,
    buf_size: usize,
    err: Option<String>,
}

impl ReadableFile {
    fn new(file: File, buf_size: usize) -> Self {
        Self {
            file,
            buf_size,
            err: None,
        }
    }
}

impl Iterator for ReadableFile {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = vec![0_u8; self.buf_size];
        let read = self.file.read(&mut buf);
        match read {
            Err(err) => {
                self.err = Some(format!("{}", err));
                None
            }
            Ok(0) => None,
            Ok(count) => Some(buf[0..count].to_vec()),
        }
    }
}

impl Streamable for ReadableFile {
    fn trailer_names(&self) -> Vec<String> {
        vec!["err".to_string()]
    }

    fn trailers(&self) -> Vec<(String, String)> {
        self.err
            .as_ref()
            .map_or_else(Vec::new, |err| vec![("err".to_string(), err.to_string())])
    }
}

fn read_file(name: &str) -> Result<Response> {
    let file = File::open(format!("/sd/data/{}", name));
    match file {
        Ok(file) => Ok(Response {
            status: 200,
            body: BodyType::StreamWithTrailers(Box::new(ReadableFile::new(file, 1024))),
            headers: None,
        }),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(Response::fixed_string(
                404,
                None,
                &format!("File '{}' does not exist", name),
            )),
            ErrorKind::PermissionDenied => Ok(Response::fixed_string(
                403,
                None,
                &format!("Access to file '{}' not allowed", name),
            )),
            _ => bail!(e),
        },
    }
}

fn file_size(name: &str) -> Result<Response> {
    let meta = fs::metadata(format!("/sd/data/{}", name));
    match meta {
        Ok(meta) => Ok(Response::fixed_string(
            200,
            None,
            format!("{}\r\n", meta.len()).as_str(),
        )),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => Ok(Response::fixed_string(
                404,
                None,
                &format!("File '{}' does not exist", name),
            )),
            ErrorKind::PermissionDenied => Ok(Response::fixed_string(
                403,
                None,
                &format!("Access to file '{}' not allowed", name),
            )),
            _ => bail!(e),
        },
    }
}

fn files() -> Result<Response> {
    let files: Vec<String> = Files::new("/sd/data")?
        .filter(|file| !file.starts_with('.'))
        .collect();
    Ok(Response::fixed_string(
        200,
        None,
        format!("{}\r\n", files.join("\r\n")).as_str(),
    ))
}

struct FileWriter {
    file: File,
}

impl FileWriter {
    fn open(name: &str) -> Result<Self> {
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(format!("/sd/data/{}", name))?;
        Ok(Self { file })
    }
}

impl RequestHandler for FileWriter {
    fn chunk(&mut self, chunk: Vec<u8>) -> HandlerResult {
        info!("write chunk {}", chunk.len());
        let write = self.file.write_all(chunk.as_slice());
        if write.is_err() {
            return HandlerResult::Abort(Response::fixed_string(500, None, "Failed to write"));
        }
        let flush = self.file.flush();
        if flush.is_err() {
            return HandlerResult::Abort(Response::fixed_string(500, None, "Failed to flush"));
        }
        HandlerResult::Continue
    }

    fn end(&mut self, _: Option<HashMap<String, String>>) -> Response {
        let close = self.file.sync_all();
        if close.is_err() {
            return Response::fixed_string(500, None, "Failed to sync");
        }
        Response::fixed_string(201, None, "")
    }
}

fn start_server() -> Result<SpawnedRestServer, HttpError> {
    let server = RestServer::new(
        "0.0.0.0".to_string(),
        8080,
        1024,
        0,
        Some(Duration::from_secs(1)),
    )?
    .get("files", |_, _| {
        let res = files();
        match res {
            Err(msg) => Response::fixed_string(500, None, format!("{}", msg).as_str()),
            Ok(res) => res,
        }
    })?
    .get("files/:name/size", |req, _| {
        let res = file_size(req.params["name"].as_str());
        match res {
            Err(msg) => Response::fixed_string(500, None, format!("{}", msg).as_str()),
            Ok(res) => res,
        }
    })?
    .get("files/:name", |req, _| {
        let res = read_file(req.params["name"].as_str());
        match res {
            Err(msg) => Response::fixed_string(500, None, format!("{}", msg).as_str()),
            Ok(res) => res,
        }
    })?
    .post("files/:name", |req, _| {
        let writer = FileWriter::open(req.params["name"].as_str());
        match writer {
            Err(msg) => CancelHandler::new(500, None, format!("{}", msg).as_str()),
            Ok(writer) => Box::new(writer),
        }
    })?;
    SpawnedRestServer::spawn(server, 8192)
}

fn load_wifi_config() -> Result<WifiConfig> {
    let file = fs::read_to_string("/sd/config/wifi.ron")?;
    let config: WifiConfig = ron::from_str(&file)?;
    Ok(config)
}

fn wifi(
    modem: impl peripheral::Peripheral<P = esp_idf_hal::modem::Modem> + 'static,
) -> Result<BlockingWifi<EspWifi<'static>>> {
    let config = load_wifi_config()?;
    println!("{:?}", config);

    let sysloop = EspSystemEventLoop::take()?;

    let mut driver = WifiDriver::new(modem, sysloop.clone(), None)?;

    driver.set_configuration(&wifi::Configuration::Client(WifiClientConfiguration {
        ssid: heapless::String::from_str(&config.ssid).unwrap(),
        password: heapless::String::from_str(&config.pw).unwrap(),
        ..Default::default()
    }))?;

    let sta_netif = EspNetif::new_with_conf(&NetifConfiguration {
        ip_configuration: IpConfiguration::Client(IpClientConfiguration::DHCP(
            DHCPClientSettings {
                hostname: Some("fileserver".try_into().unwrap()),
            },
        )),
        ..NetifStack::Sta.default_configuration()
    })?;
    let ap_netif = EspNetif::new(NetifStack::Ap)?;

    let mut wifi = BlockingWifi::wrap(EspWifi::wrap_all(driver, sta_netif, ap_netif)?, sysloop)?;

    println!("Starting wifi...");
    wifi.start()?;

    println!("Connecting wifi...");
    wifi.connect()?;

    println!("Waiting for DHCP lease...");
    wifi.wait_netif_up()?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    println!("Wifi DHCP info: {:?}", ip_info);

    Ok(wifi)
}
