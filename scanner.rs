extern crate log;
extern crate winapi;

use winapi::um::handleapi::CloseHandle;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

pub fn get_pid(exe_name: &str) -> Option<u32> {
    log::info!("creating snapshot for processes");
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        log::error!("failed to create process snapshot");
        return None;
    }

    let mut pe32: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
    let mut pid = None;

    if unsafe { Process32First(snap, &mut pe32) } == winapi::shared::minwindef::TRUE {
        loop {
            let exe_name_cstr = unsafe { std::ffi::CStr::from_ptr(pe32.szExeFile.as_ptr()) }
                .to_str()
                .unwrap();
            log::info!("found process: {}", exe_name_cstr);
            if exe_name_cstr == exe_name {
                pid = Some(pe32.th32ProcessID);
                break;
            }
            if unsafe { Process32Next(snap, &mut pe32) } == winapi::shared::minwindef::FALSE {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap) };
    pid
}
