extern crate log;
extern crate winapi;

use log::info;
use std::fs::File;
use std::io::{self, Write};
use std::ptr;
use winapi::shared::minwindef::{BOOL, FALSE, TRUE};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::{OpenProcess, PROCESS_ALL_ACCESS};
use winapi::um::psapi::GetProcessImageFileNameW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
use winapi::um::winuser::{FindWindowW, GetWindowThreadProcessId};

pub fn pid_wind(window_name: &str) -> Option<u32> {
    info!("finding wind: {}", window_name);
    let hwnd = unsafe { FindWindowW(ptr::null(), to_wide(window_name).as_ptr()) };
    if hwnd.is_null() {
        log::error!("failed to find wind: {}", window_name);
        return None;
    }
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    info!("scoped target: {}", pid);
    Some(pid)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn get_process_name(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = [0u16; 260];
    let length =
        unsafe { GetProcessImageFileNameW(handle, buffer.as_mut_ptr(), buffer.len() as u32) };
    unsafe { CloseHandle(handle) };

    if length > 0 {
        Some(String::from_utf16_lossy(&buffer[..length as usize]))
    } else {
        None
    }
}

fn dump_memory(pid: u32, output_file: &str) -> io::Result<()> {
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    if process_handle.is_null() {
        return Err(io::Error::new(io::ErrorKind::Other, "failed to open proc"));
    }

    let mut address = 0;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut file = File::create(output_file)?;

    loop {
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let mut buffer = vec![0; mbi.RegionSize];
        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                mbi.RegionSize,
                &mut bytes_read,
            );
        }

        file.write_all(&buffer)?;
        address += mbi.RegionSize;
    }

    unsafe { CloseHandle(process_handle) };
    Ok(())
}

fn main() {
    env_logger::init();
    let window_name = "Roblox";
    if let Some(pid) = pid_wind(window_name) {
        match get_process_name(pid) {
            Some(name) => {
                info!("proc name: {}", name);
                match dump_memory(pid, "rbx.bin") {
                    Ok(_) => info!("mem dump dun"),
                    Err(e) => log::error!("mem dump fked: {}", e),
                }
            }
            None => log::error!("failed to get proc name ;?"),
        }
    }
}
