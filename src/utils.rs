#![allow(non_snake_case)]
pub mod proc {
    use std::mem::{size_of, zeroed};

    use windows::{
        core::{PCSTR, PCWSTR, PWSTR},
        s, w,
        Win32::{
            Foundation::{
                CloseHandle, BOOL, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, LUID,
                PSID,
            },
            Security::{
                AdjustTokenPrivileges, AllocateAndInitializeSid, CheckTokenMembership, FreeSid,
                ImpersonateSelf, LookupPrivilegeValueA, SecurityImpersonation,
                SE_PRIVILEGE_ENABLED, SID_IDENTIFIER_AUTHORITY, TOKEN_ADJUST_PRIVILEGES,
                TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
            },
            System::{
                Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_NONE, HEAP_ZERO_MEMORY},
                SystemServices::{DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID},
                Threading::{
                    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
                    GetCurrentThread, InitializeProcThreadAttributeList, OpenProcessToken,
                    OpenThreadToken, UpdateProcThreadAttribute, CREATE_UNICODE_ENVIRONMENT,
                    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
                    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    STARTF_USESHOWWINDOW, STARTUPINFOEXW,
                },
            },
            UI::{
                Shell::ShellExecuteW,
                WindowsAndMessaging::{SW_SHOW, SW_SHOWDEFAULT},
            },
        },
    };

    const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

    // check whether current process privilege is elevated
    #[rustfmt::skip]
    pub unsafe fn is_elevated() -> bool {
        let mut admins_group = zeroed::<PSID>();
        let mut authority = zeroed::<SID_IDENTIFIER_AUTHORITY>();
        authority.Value = SECURITY_NT_AUTHORITY;

        match AllocateAndInitializeSid(
            &mut authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID.try_into().unwrap(),
            DOMAIN_ALIAS_RID_ADMINS.try_into().unwrap(),
            0, 0, 0, 0, 0, 0,
            &mut admins_group,
        ).ok()
        {
            Ok(()) => {
                let mut is_member: BOOL = BOOL(0);
                match CheckTokenMembership(None, admins_group, &mut is_member).ok() {
                    Ok(()) => {
                        FreeSid(admins_group);
                        if is_member.as_bool() {
                            true
                        } else {
                            false
                        }
                    }
                    Err(_) => {
                        FreeSid(admins_group);
                        false
                    },
                }
            }
            Err(_) => false,
        }
    }

    // elevate to admin priv
    pub unsafe fn elevate_to_admin() {
        if !is_elevated() {
            let mut us_filename: Vec<_> = std::env::args()
                .nth(0)
                .unwrap()
                .encode_utf16()
                .collect::<Vec<_>>();
            us_filename.push(0x0);

            let mut us_cmdline: Vec<_> = std::env::args()
                .skip(1)
                .map(|x| format!("\"{}\"", x))
                .collect::<Vec<_>>()
                .join(" ")
                .encode_utf16()
                .collect();
            us_cmdline.push(0x0);

            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR::from_raw(us_filename.as_ptr()),
                PCWSTR::from_raw(us_cmdline.as_ptr()),
                None,
                SW_SHOWDEFAULT,
            );
            std::process::exit(0);
        }
    }

    // enable or disable token privilege
    pub unsafe fn set_privilege(
        token: HANDLE,
        privilege_name: PCSTR,
        enabled: bool,
    ) -> Result<(), windows::core::Error> {
        // 获取权限id
        let mut luid = zeroed::<LUID>();
        LookupPrivilegeValueA(None, privilege_name, &mut luid).ok()?;

        // 设置token权限
        let mut tp = zeroed::<TOKEN_PRIVILEGES>();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = if enabled {
            SE_PRIVILEGE_ENABLED
        } else {
            TOKEN_PRIVILEGES_ATTRIBUTES(0x0)
        };

        AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            size_of::<TOKEN_PRIVILEGES>() as _,
            None,
            None,
        )
        .ok()?;

        Ok(())
    }

    // enable current process debug privilege
    pub unsafe fn enable_debug_priv() -> Result<(), windows::core::Error> {
        let mut proc_handle = INVALID_HANDLE_VALUE;
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut proc_handle,
        )
        .ok()?;
        set_privilege(proc_handle, s!("SeDebugPrivilege"), true)?;
        CloseHandle(proc_handle);

        Ok(())
    }

    // enable current thread debug privilege
    pub unsafe fn t_enable_debug_priv() -> Result<(), windows::core::Error> {
        let mut thread_handle = INVALID_HANDLE_VALUE;
        ImpersonateSelf(SecurityImpersonation).ok()?;
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            true,
            &mut thread_handle,
        )
        .ok()?;
        set_privilege(thread_handle, s!("SeDebugPrivilege"), true)?;
        CloseHandle(thread_handle);

        Ok(())
    }

    // create new process using parent process handle
    pub unsafe fn create_process_with_handle(
        handle: HANDLE,
        cmdline: &str,
    ) -> Result<u32, windows::core::Error> {
        let mut si: STARTUPINFOEXW = zeroed();
        let mut pi: PROCESS_INFORMATION = zeroed();
        let mut size: usize = 0x30;

        loop {
            if size > 1024 {
                return Err(windows::core::Error::from_win32());
            }

            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(HeapAlloc(
                GetProcessHeap().unwrap(),
                HEAP_ZERO_MEMORY,
                size,
            ));

            if si.lpAttributeList.is_invalid() {
                return Err(windows::core::Error::from_win32());
            }
            let ret =
                match InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &mut size).ok() {
                    Ok(()) => {
                        UpdateProcThreadAttribute(
                            si.lpAttributeList,
                            0,
                            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                            Some(&handle as *const _ as *mut _),
                            size_of::<HANDLE>(),
                            None,
                            None,
                        )
                        .ok()?;

                        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                        si.StartupInfo.wShowWindow = SW_SHOW.0 as _;

                        let mut us_cmdline: Vec<_> = cmdline.encode_utf16().collect();
                        us_cmdline.push(0x0);

                        CreateProcessW(
                            None,
                            PWSTR::from_raw(us_cmdline.as_mut_ptr()),
                            None,
                            None,
                            false,
                            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                            None,
                            None,
                            &mut si.StartupInfo,
                            &mut pi,
                        )
                        .ok()?;

                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);

                        Ok(pi.dwProcessId)
                    }
                    // Err(windows::core::Error::from(ERROR_INSUFFICIENT_BUFFER)) => {}
                    Err(e) => {
                        if e != windows::core::Error::from(ERROR_INSUFFICIENT_BUFFER) {
                            Err(e)
                        } else {
                            Ok(0)
                        }
                    }
                };

            if !si.lpAttributeList.is_invalid() {
                DeleteProcThreadAttributeList(si.lpAttributeList);
            }
            HeapFree(
                GetProcessHeap().unwrap(),
                HEAP_NONE,
                Some(si.lpAttributeList.0),
            );

            match ret {
                Ok(0) => {
                    continue;
                }
                Ok(pid) => {
                    return Ok(pid);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}
