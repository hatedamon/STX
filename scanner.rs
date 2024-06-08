extern crate log;
extern crate winapi;

use winapi::um::handleapi::CloseHandle;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winuser::{FindWindowW, GetWindowThreadProcessId};

pub fn pid_wind(window_name: &str) -> Option<u32> {
    log::info!("finding window with name: {}", window_name);
    let hwnd = unsafe { FindWindowW(std::ptr::null(), window_name.as_ptr() as *const u16) };
    if hwnd.is_null() {
        log::error!("failed to find window with name: {}", window_name);
        return None;
    }
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    log::info!("found target: {}", pid);
    Some(pid)
}
