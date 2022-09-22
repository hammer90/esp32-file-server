use std::ffi::{CStr, CString};

use anyhow::{bail, Result};
use esp_idf_sys::{opendir, readdir, DIR};

pub struct Files {
    ptr: *mut DIR,
}

impl Files {
    pub fn new(location: &str) -> Result<Self> {
        let p = CString::new(location)?;
        unsafe {
            let ptr = opendir(p.as_ptr());
            if ptr.is_null() {
                bail!("opendir returned null");
            }
            Ok(Self { ptr })
        }
    }
}

impl Iterator for Files {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let dir = readdir(self.ptr);
            if dir.is_null() {
                return None;
            }
            let name = CStr::from_ptr(&(*dir).d_name[0]);
            let file_name = name.to_string_lossy().to_string();
            Some(file_name)
        }
    }
}
