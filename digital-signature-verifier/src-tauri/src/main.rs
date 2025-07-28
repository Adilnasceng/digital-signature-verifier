#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::fs;
use std::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::um::wintrust::{
    WinVerifyTrust, WINTRUST_FILE_INFO, WINTRUST_DATA, WTD_UI_NONE, WTD_CHOICE_FILE,
    
};
use winapi::shared::winerror::{TRUST_E_NOSIGNATURE, ERROR_SUCCESS};
use winapi::shared::guiddef::GUID;
use winapi::shared::windef::HWND;
use winapi::shared::minwindef::LPVOID;

// Kendi GUID tanımınızı ekleyin
pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    Data1: 0xaac56b,
    Data2: 0xcd44,
    Data3: 0x11d0,
    Data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

fn to_lpcwstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect()
}

fn verify_file_signature(file_path: &str) -> Result<(), u32> {
    let file_path_w: Vec<u16> = to_lpcwstr(file_path);

    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: file_path_w.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null(),
    };

    let mut wintrust_data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    wintrust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = 0;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.dwStateAction = 0;
    wintrust_data.hWVTStateData = ptr::null_mut();
    wintrust_data.pwszURLReference = ptr::null_mut();
    wintrust_data.dwProvFlags = 0;
    wintrust_data.dwUIContext = 0;

    // Set the `u` union field's `pFile` pointer to `file_info`
    unsafe {
        *wintrust_data.u.pFile_mut() = &file_info as *const _ as *mut WINTRUST_FILE_INFO;
    }

    let action_id: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut() as HWND, // Handle to parent window (use `null_mut()` for no parent window)
            &action_id as *const _ as *mut GUID,
            &wintrust_data as *const _ as LPVOID,
        )
    };

    if status == ERROR_SUCCESS as i32 {
        Ok(())
    } else {
        Err(status as u32)
    }
}

fn verify_directory_recursive<P: AsRef<std::path::Path>>(path: P, results: &mut String) {
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_file() {
                            match verify_file_signature(path.to_str().unwrap()) {
                                Ok(_) => {
                                    results.push_str(&format!("Verified: {}\n", path.display()));
                                }
                                Err(err) => {
                                    if err == TRUST_E_NOSIGNATURE as u32 {
                                        results.push_str(&format!("No signature: {}\n", path.display()));
                                    }
                                }
                            }
                        } else if path.is_dir() {
                            verify_directory_recursive(&path, results);
                        }
                    }
                    Err(e) => {
                        results.push_str(&format!("Failed to read entry: {}\n", e));
                    }
                }
            }
        }
        Err(e) => {
            results.push_str(&format!("Could not read the directory: {}\n", e));
        }
    }
}

#[tauri::command]
fn verify_certificates() -> String {
    let folder_path = r"C:\\Users\\fbli_\\Downloads\\Programs";
    let mut results = String::new();

    verify_directory_recursive(folder_path, &mut results);

    results
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![verify_certificates])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
