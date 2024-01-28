# esp32-file-server

A demo binary crate for the ESP32 and ESP-IDF, which mounts a SD card and grants access to the stored files via a RESTful API.

## Hardware

For access to the SD card the SDMMC interface is used which  exists on ESP32/ESP32-S3 but **NOT** on ESP32-S2/ESP32-C3.
However esp32-file-server is only tested on an ESP32.
For detailed information on the wiring please consult the [official examples by espressif](https://github.com/espressif/esp-idf/tree/master/examples/storage/sd_card/sdmmc).

## Build

For the build process the pure cargo approach with [esp-idf-sys](https://crates.io/crates/esp-idf-sys) and [embuild](https://crates.io/crates/embuild) is used as described in [rust-esp32-std-demo](https://github.com/ivmarkov/rust-esp32-std-demo).

There is a tight dependency between the ESP-IDF version and the version of the Rust wrappers [esp-idf-sys](https://crates.io/crates/esp-idf-sys), [esp-idf-svc](https://crates.io/crates/esp-idf-svc) and [esp-idf-hal](https://crates.io/crates/esp-idf-hal).
To achieve reproducible builds the ESP-IDF version is fixed to a Tag inside [.cargo/config.toml](.cargo/config.toml) and not to a volatile release branch.

## Partion layout

The first FAT32 formatted partition will be used.
Other partitions (non FAT32 partitions and additional FAT32 partitions) will be ignored.

The first FAT32 partition must contain a `config` and a `data` folder.
The `data` filder will be aviable by the api.
The `config` folder must contain a `wifi.ron` file with the WLAN credentails:

```rust
(
ssid: "your ssid",
pw: "your wlan password",
)

```

Last compiled with v1.75.0-nightly.
