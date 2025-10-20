use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::Foundation::{HANDLE, CloseHandle};

pub fn get_process_pid(name: &str) -> Result<u32, String> {
    for proc_info in list_processes()
        .map_err(|e| format!("Unable to list processes: {}", e))?
        .iter()
    {
        if proc_info.name.to_lowercase() == name {
            return Ok(proc_info.pid);
        }
    }

    return Err(format!("Unable to find {} process", name));
}

pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

pub fn list_processes() -> windows::core::Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();
    let snapshot: HANDLE =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

    let mut process_entry: PROCESSENTRY32 = PROCESSENTRY32::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    // Get the first process in the snapshot
    if unsafe { Process32First(snapshot, &mut process_entry).is_ok() } {
        loop {
            let pid = process_entry.th32ProcessID;

            let name = unsafe {
                str::from_utf8(std::slice::from_raw_parts(
                    process_entry.szExeFile.as_ptr() as *const u8,
                    process_entry
                        .szExeFile
                        .iter()
                        .position(|&x| x == 0)
                        .unwrap_or(256),
                ))
                .unwrap()
                .to_string()
            };

            processes.push(ProcessInfo {pid, name});

            // Get the next process in the snapshot
            if !unsafe { Process32Next(snapshot, &mut process_entry).is_ok() } {
                break;
            }
        }
    }

    // Close the snapshot handle
    unsafe {
        let _ = CloseHandle(snapshot);
    };

    Ok(processes)
}


