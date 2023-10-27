// Microsoft Windows family abstractions..
use errno::errno;
use std::{ffi::c_void, ptr};
use windows;
use windows::Win32::{
    Foundation,
    Storage::FileSystem,
    System::SystemInformation,
    System::{Diagnostics::Debug, Memory, SystemServices::MAXDWORD, IO},
};

pub type File = Foundation::HANDLE;
pub type Void = c_void;

macro_rules! result {
    ( $rval:expr ) => {{
        let r = unsafe { $rval };
        match r {
            Err(_) => Err(std::io::Error::last_os_error()),
            Ok(r) => Ok(r),
        }
    }};
}

// Panic on file problems.
macro_rules! panic_syserr {
    ( $rval:expr ) => {{
        let r = unsafe { $rval };
        match r {
            Err(_) => {
                let e = errno();
                panic!("System error #{:x}: {}", e.0, e);
            }
            Ok(r) => r,
        }
    }};
}
macro_rules! panic_syserr_invalid {
    ( $rval:expr, $invalid:expr ) => {{
        let r = unsafe { $rval };
        if r == $invalid {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
        r
    }};
}

pub fn page_size() -> usize {
    let mut si = SystemInformation::SYSTEM_INFO::default();
    unsafe { SystemInformation::GetSystemInfo(&mut si) };
    si.dwPageSize.try_into().unwrap()
}

pub fn open(pathname: &String) -> std::io::Result<File> {
    let pn: Vec<u16> = pathname.encode_utf16().collect();
    result!(FileSystem::CreateFileW(
        windows::core::PCWSTR::from_raw(pn.as_ptr()),
        (Foundation::GENERIC_READ | Foundation::GENERIC_WRITE).0,
        FileSystem::FILE_SHARE_READ | FileSystem::FILE_SHARE_WRITE,
        None,
        FileSystem::OPEN_ALWAYS,
        FileSystem::FILE_ATTRIBUTE_NORMAL,
        Foundation::INVALID_HANDLE_VALUE,
    ))
}

pub unsafe fn read(f: File, buf: *mut Void, size: usize) -> usize {
    let mut rval: u32 = 0;
    let b = Some(std::slice::from_raw_parts_mut(buf as *mut u8, size));
    panic_syserr!(FileSystem::ReadFile(f, b, Some(&mut rval), None));
    rval.try_into().unwrap()
}

pub unsafe fn write_page(f: File, pno: u32, page: *const Void, psize: usize) {
    let ppno = std::ptr::from_ref(&pno) as *const u8;
    let bno = Some(std::slice::from_raw_parts(ppno, 4));
    let mut wrtn: u32 = 0;
    panic_syserr!(FileSystem::WriteFile(f, bno, Some(&mut wrtn), None));
    assert_eq!(wrtn, 4);
    let bpg = Some(std::slice::from_raw_parts(page as *const u8, psize));
    panic_syserr!(FileSystem::WriteFile(f, bpg, Some(&mut wrtn), None));
    assert_eq!(wrtn as usize, psize);
}

pub fn close(f: File) {
    panic_syserr!(Foundation::CloseHandle(f));
}

pub fn seek_begin(f: File) {
    panic_syserr_invalid!(
        FileSystem::SetFilePointer(f, 0, None, FileSystem::FILE_BEGIN),
        FileSystem::INVALID_SET_FILE_POINTER
    );
}

// MapHolder: RAII fixture to handle file memory mapping.
#[derive(std::fmt::Debug)]
pub struct MapHolder {
    pub arena: *mut Void,
    pub size: usize,
    file_mapping: Foundation::HANDLE,
    mapped_view: Memory::MEMORY_MAPPED_VIEW_ADDRESS,
}

impl MapHolder {
    pub fn new(
        f: File,
        a: *const Void,
        s: usize,
    ) -> std::io::Result<MapHolder> {
        #[cfg(target_pointer_width = "32")]
        let (hi, lo) = (0, s as u32);
        #[cfg(target_pointer_width = "64")]
        let (hi, lo) = ((s >> 32) as u32, s as u32);
        const F: Memory::PAGE_PROTECTION_FLAGS = Memory::PAGE_READWRITE;
        let fm = result!(Memory::CreateFileMappingA(f, None, F, hi, lo, None))?;
        eprintln!("MapHolder::new address my {a:p}");
        let a = if a.is_null() { None } else { Some(a) };
        let m = unsafe {
            Memory::MapViewOfFileEx(fm, Memory::FILE_MAP_ALL_ACCESS, 0, 0, s, a)
        };
        eprintln!("MapHolder::new address real {:p}", m.Value);
        if m.Value.is_null() {
            eprintln!("MapHolder::new {}", unsafe {
                Foundation::GetLastError().unwrap_err()
            });
            panic_syserr!(Foundation::CloseHandle(fm));
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Uncategorized {
                Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            } else {
                Err(e)
            }
        } else {
            unsafe { mprotect_r(m.Value, s) };
            Ok(MapHolder {
                arena: m.Value,
                size: s,
                file_mapping: fm,
                mapped_view: m,
            })
        }
    }
}

impl Drop for MapHolder {
    fn drop(&mut self) {
        panic_syserr!(Memory::UnmapViewOfFile(self.mapped_view));
        panic_syserr!(Foundation::CloseHandle(self.file_mapping));
    }
}

pub unsafe fn mprotect_rw(a: *const Void, s: usize) {
    let mut f: Memory::PAGE_PROTECTION_FLAGS = Default::default();
    panic_syserr!(Memory::VirtualProtect(a, s, Memory::PAGE_READWRITE, &mut f));
}

pub unsafe fn mprotect_r(a: *const Void, s: usize) {
    let mut f: Memory::PAGE_PROTECTION_FLAGS = Default::default();
    panic_syserr!(Memory::VirtualProtect(a, s, Memory::PAGE_READONLY, &mut f));
}

// Making log file ready for the next transaction.
pub fn truncate(f: File) {
    panic_syserr_invalid!(
        FileSystem::SetFilePointer(f, 0, None, FileSystem::FILE_BEGIN),
        FileSystem::INVALID_SET_FILE_POINTER
    );
    panic_syserr!(FileSystem::SetEndOfFile(f));
}

pub fn enlarge(f: File, offset: usize) {
    panic_syserr!(FileSystem::SetFilePointerEx(
        f,
        offset as i64,
        None,
        FileSystem::FILE_BEGIN
    ));
    panic_syserr!(FileSystem::SetEndOfFile(f));
}

// Check if the log file is not empty.
// Remember, the log file offset must be at the end of file.
pub fn not_empty(f: File) -> bool {
    let mut lpfs: i64 = 0;
    panic_syserr!(FileSystem::GetFileSizeEx(f, &mut lpfs));
    lpfs > 0
}

// File sync
pub fn sync(lfd: File) {
    panic_syserr!(FileSystem::FlushFileBuffers(lfd));
}

// Flock the main file.
pub fn flock_w(fd: File) {
    panic_syserr!(FileSystem::LockFile(fd, 0, 0, MAXDWORD, MAXDWORD));
}
pub fn flock_r(fd: File) {
    let mut o = IO::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: IO::OVERLAPPED_0 { Pointer: ptr::null_mut() },
        hEvent: Foundation::HANDLE(0),
    };
    let fl = FileSystem::LOCK_FILE_FLAGS(0);
    let m = MAXDWORD;
    panic_syserr!(FileSystem::LockFileEx(fd, fl, 0, m, m, &mut o));
}
pub fn unflock(fd: File) {
    panic_syserr!(FileSystem::UnlockFile(fd, 0, 0, MAXDWORD, MAXDWORD));
}

// Top level exception filter: install/remove it on crate load/remove.
static mut OLDFILTER: Debug::LPTOP_LEVEL_EXCEPTION_FILTER = None;

fn er_to_addr(er: Debug::EXCEPTION_RECORD) -> *const Void {
    assert_eq!(er.ExceptionRecord, ptr::null_mut());
    er.ExceptionInformation[1] as *const Void
}

unsafe extern "system" fn filter(
    info: *const Debug::EXCEPTION_POINTERS,
) -> i32 {
    let er = info.as_ref().unwrap().ExceptionRecord;
    let ok = match (*er).ExceptionCode {
        /* Foundation::EXCEPTION_IN_PAGE_ERROR => {
            let addr = er_to_addr(*er);
            MEMORY_VIOLATION_HANDLER.unwrap()(addr, true)
        } */
        Foundation::EXCEPTION_ACCESS_VIOLATION => {
            let addr = er_to_addr(*er);
            MEMORY_VIOLATION_HANDLER.unwrap()(addr, false)
        }
        _ => false,
    };
    if ok {
        // Cannot use Kernel::ExceptionContinueExecution.0, because it is 0.
        const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        // Cannot use Kernel::ExceptionContinueSearch.0, because it is 1.
        const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
        match unsafe { OLDFILTER } {
            None => EXCEPTION_CONTINUE_SEARCH,
            Some(oldfilter) => oldfilter(info),
        }
    }
}

pub type MemoryViolationHandler =
    unsafe fn(addr: *const Void, extend: bool) -> bool;
static mut MEMORY_VIOLATION_HANDLER: Option<MemoryViolationHandler> = None;

pub unsafe fn initialize_memory_violation_handler(h: MemoryViolationHandler) {
    assert_eq!(unsafe { OLDFILTER }, None);
    let old = Debug::SetUnhandledExceptionFilter(Some(filter));
    MEMORY_VIOLATION_HANDLER = Some(h);
    OLDFILTER = old;
}

pub unsafe fn finalize_memory_violation_handler() {
    let old = OLDFILTER;
    let my = Debug::SetUnhandledExceptionFilter(old);
    assert!(my == Some(filter));
    OLDFILTER = None;
}
