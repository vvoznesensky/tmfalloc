// Microsoft Windows family abstractions.
use checked_int_cast::CheckedIntCast;
use errno;
use windows_sys::{
    Handle,
    Win32::{
        Foundation,
        Storage::FileSystem,
        System::Kernel,
        System::{Diagnostics::Debug, Memory, SystemServices::MAXDWORD, IO},
    },
};

pub type File = Handle;
pub type Void = c_void;

macro_rules! result {
    ( $rval:expr, $invalid_handle ) => {{
        let r = unsafe { $rval };
        if r == $invalid_handle {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }};
}

// Panic on file problems.
macro_rules! panic_syserr {
    ( $rval:expr ) => {{
        if !unsafe { $rval } {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
    }};
}
macro_rules! panic_syserr_invalid {
    ( $rval:expr, $invalid:expr ) => {{
        if unsafe { $rval } == $invalid {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
    }};
}

pub fn open(pathname: &String) -> std::io::Result<File> {
    result!(
        FileSystem::CreateFileA(
            pathname.as_ptr(),
            Foundation::GENERIC_READ | Foundation::GENERIC_WRITE,
            FileSystem::FILE_SHARE_READ | FileSystem::FILE_SHARE_WRITE,
            None,
            FileSystem::OPEN_ALWAYS,
            FileSystem::FILE_ATTRIBUTE_NORMAL,
            None
        ),
        Foundation::INVALID_HANDLE_VALUE
    )
}

pub unsafe fn read(f: File, buf: *mut Void, s: usize) -> usize {
    let mut rval: u32;
    panic_syserr!(FileSystem::read(f, buf, s, &mut rval));
    rval
}

pub fn write_page(f: File, pno: u32, page: *const Void, psize: usize) {
    let mut wrtn: u32;
    panic_syserr!(FileSystem::WriteFile(f, &pno as *const u8, 4, &wrtn, None));
    assert_eq!(wrtn, 4);
    let ps = psize.as_u32_checked().unwrap();
    panic_syserr!(FileSystem::WriteFile(f, page as *const u8, ps, &wrtn, None));
    assert_eq!(wrtn, ps);
}

pub fn close(f: File) {
    panic_syserr!(FileSystem::CloseHandle(f));
}

pub fn seek_begin(f: File) {
    panic_syserr_invalid!(
        FileSystem::SetFilePointer(f, 0, None, FileSystem::FILE_BEGIN),
        FileSystem::INVALID_SET_FILE_POINTER
    );
}

// MapHolder: RAII fixture to handle file memory mapping.
#[derive(Debug)]
pub struct MapHolder {
    pub arena: *mut Void,
    pub size: usize,
    file_mapping: Foundation::HANDLE,
    mapped_view: Memory::MEMORYMAPPEDVIEW_HANDLE,
}

impl MapHolder {
    pub fn new(
        f: File,
        a: *mut Void,
        size: usize,
    ) -> std::io::Result<MapHolder> {
        #[cfg(target_pointer_width = "32")]
        let (hi, lo) = (0, size as u32);
        #[cfg(target_pointer_width = "64")]
        let (hi, lo) = ((size >> 32) as u32, size as u32);
        const MPRW: Memory::PAGE_PROTECTION_FLAGS = Memory::PAGE_READWRITE;
        let fm = result!(Memory::CreateFileMappingA(f, None, MPRW, hi, lo, a))?;
        match Memory::MapViewOfFileEx(fm, Memory::FILE_MAP_READ, 0, 0, size, a)
        {
            0 => {
                panic_syserr!(Foundation::CloseHandle(fm));
                Err(std::io::Error::last_os_error())
            }
            mv => Ok(MapHolder {
                arena: mv as *mut Void,
                size,
                file_mapping: fm,
                mapped_view: mv,
            }),
        }
    }
}

impl Drop for MapHolder {
    fn drop(&mut self) {
        panic_syserr!(Memory::UnmapViewOfFile(self.mapped_view));
        panic_syserr!(Foundation::CloseHandle(self.file_mapping));
    }
}

pub fn mprotect_rw(a: *mut Void, s: usize) {
    let _ppf: Memory::PAGE_PROTECTION_FLAGS;
    panic_syserr!(Memory::VirtualProtect(a, s, Memory::PAGE_READWRITE, &_ppf));
}

pub fn mprotect_r(a: *mut Void, s: usize) {
    let _ppf: Memory::PAGE_PROTECTION_FLAGS;
    panic_syserr!(Memory::VirtualProtect(a, s, Memory::PAGE_READ, &_ppf));
}

pub fn mprotect_w(a: *mut Void, s: usize) {
    let _ppf: Memory::PAGE_PROTECTION_FLAGS;
    panic_syserr!(Memory::VirtualProtect(a, s, Memory::PAGE_WRITE, &_ppf));
}

// Making log file ready for the next transaction.
pub fn truncate(f: File) {
    panic_syserr_invalid!(
        FileSystem::SetFilePointer(f, 0, None, FileSystem::FILE_BEGIN),
        FileSystem::INVALID_SET_FILE_POINTER
    );
    panic_syserr!(FileSystem::SetEndOfFile(f));
}

pub fn enlarge(fd: File, offset: usize) {
    panic_syserr!(FileSystem::SetFilePointerEx(
        f,
        offset as i64,
        None,
        FileSystem::FILE_BEGIN
    ),);
    panic_syserr!(FileSystem::SetEndOfFile(f));
}

// Check if the log file is not empty.
// Remember, the log file offset must be at the end of file.
pub fn not_empty(f: File) -> bool {
    let lpfs: i64;
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
    let o = FileSystem::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: None,
        hEvent: 0,
    };
    let fl = FileSystem::LOCKFILE_EXCLUSIVE_LOCK;
    panic_syserr!(FileSystem::LockFileEx(fd, fl, 0, MAXDWORD, MAXDWORD, &o));
}
pub fn unflock(fd: File) {
    panic_syserr!(FileSystem::UnlockFile(fd, 0, 0, MAXDWORD, MAXDWORD));
}

// Top level exception filter: install/remove it on crate load/remove.
static mut OLDFILTER: LPTOP_LEVEL_EXCEPTION_FILTER = None;

fn er_to_addr(er: Debug::ExceptionRecord) -> *const Void {
    assert_eq!(er.ExceptionRecord, None);
    er.ExceptionInformation[1] as *const Void;
}

unsafe extern "system" fn filter(
    info: *const Debug::EXCEPTION_POINTERS,
) -> i32 {
    let er = info.as_ref().unwrap().ExceptionRecord;
    let ok = match er.ExceptionCode {
        Foundation::EXCEPTION_IN_PAGE_ERROR => {
            let addr = er_to_addr();
            unsafe { MEMORY_VIOLATION_HANDLER.unwrap()(addr, true) }
        }
        Foundation::EXCEPTION_ACCESS_VIOLATION => {
            let addr = er_to_addr();
            unsafe { MEMORY_VIOLATION_HANDLER.unwrap()(addr, false) }
        }
        _ => false,
    };
    if ok {
        Kernel::ExceptionContinueExecution
    } else {
        unsafe { OLDFILTER.unwrap_or_else(|info| {})(info) }
    }
}

pub type MemoryViolationHandler = fn(addr: *const Void, extend: bool) -> bool;
static mut MEMORY_VIOLATION_HANDLER: Option<MemoryViolationHandler> = None;

pub unsafe fn initialize_memory_violation_handler(h: MemoryViolationHandler) {
    assert_eq!(unsafe { OLDFILTER }, None);
    let old = Debug::SetUnhandledExceptionFilter(Some(filter));
    unsafe {
        MEMORY_VIOLATION_HANDLER = Some(h);
    }
    unsafe {
        OLDFILTER = old;
    }
}

pub unsafe fn finalize_memory_violation_handler() {
    let old = unsafe { OLDFILTER };
    let my = Debug::SetUnhandledExceptionFilter(old);
    unsafe {
        OLDFILTER = None;
    }
}
