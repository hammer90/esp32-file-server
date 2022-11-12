#![allow(clippy::single_component_path_imports)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use embeddable_rest_server::{
    BodyType, CancelHandler, HandlerResult, HttpError, RequestHandler, Response, RestServer,
    SpawnedRestServer, Streamable,
};
use embedded_svc::wifi::Configuration;
use esp_idf_svc::netif::EspNetifStack;
use esp_idf_svc::sntp;
use esp_idf_svc::sysloop::EspSysLoopStack;
use log::*;

use esp_idf_hal::peripherals::Peripherals;

use esp_idf_svc::wifi::*;

use embedded_svc::ipv4::ClientConfiguration::*;
use embedded_svc::ipv4::DHCPClientSettings;
use embedded_svc::wifi::*;
use esp32_sdcard::*;
use esp_idf_svc::nvs::*;

mod readdir;
use readdir::Files;

fn main() -> Result<()> {
    esp_idf_sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().ok_or_else(|| anyhow!("no input pins"))?;

    let pins = SdPins {
        cmd: peripherals.pins.gpio15.into_input()?,
        clk: peripherals.pins.gpio14.into_input()?,
        d0: peripherals.pins.gpio2.into_input()?,
        d1: peripherals.pins.gpio4.into_input()?,
        d2: peripherals.pins.gpio12.into_input()?,
        d3: peripherals.pins.gpio13.into_input()?,
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

    let netif_stack = Arc::new(EspNetifStack::new()?);
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    let default_nvs = Arc::new(EspDefaultNvs::new()?);

    let _wifi = wifi(netif_stack, sys_loop_stack, default_nvs)?;

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
    let server = RestServer::new("0.0.0.0".to_string(), 8080, 1024, 0)?
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

fn duration_since_boot() -> Duration {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO)
}

fn wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let mut wifi = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);

    info!("Wifi created, about to connect...");

    let config = load_wifi_config()?;
    println!("{:?}", config);
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: config.ssid,
        password: config.pw,
        ip_conf: Some(DHCP(DHCPClientSettings {
            hostname: Some("fileserver".into()),
        })),
        ..Default::default()
    }))?;

    wifi.wait_status_with_timeout(Duration::from_secs(20) + duration_since_boot(), |status| {
        !status.is_transitional()
    })
    .map_err(|e| anyhow::anyhow!("Unexpected Wifi status while waiting: {:?}", e))?;

    let status = wifi.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(
            _ip_settings,
        ))),
        _,
    ) = status
    {
        info!("Wifi connected");
    } else {
        bail!("Unexpected Wifi status after waiting: {:?}", status);
    }
    Ok(wifi)
}
