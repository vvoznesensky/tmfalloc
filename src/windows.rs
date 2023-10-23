// Microsoft Windows family abstractions.
use checked_int_cast::CheckedIntCast;
use errno;
use windows_sys::{
    Handle,
    Win32::{Foundation, Storage::FileSystem, System::Memory, System::IO},
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
    panic_syserr!(FileSystem::LockFile(fd, 0, 0, 1, 0));
}
pub fn flock_r(fd: File) {
    panic_syserr!(FileSystem::LockFileEx(fd, fl, 0, 1, 0, XXX));
    flock(fd, 0);
    flock(fd, FileSystem::LOCKFILE_EXCLUSIVE_LOCK);
}
pub fn unflock(fd: File) {
    panic_syserr!(FileSystem::UnlockFile(fd, 0, 0, 1, 0));
}

// Sigaction stuff: signal handler, install/remove it on crate load/remove.
static mut OLDACTSEGV: Option<SigAction> = None;
static mut OLDACTBUS: Option<SigAction> = None;

extern "C" fn sighandler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut c_void,
) {
    let addr = unsafe { info.as_ref().unwrap().si_addr() } as *const Void;
    let extend = signum == libc::SIGBUS;
    if unsafe { MEMORY_VIOLATION_HANDLER.unwrap()(addr, extend) } {
        return;
    };
    let oa = if signum == libc::SIGSEGV {
        unsafe { OLDACTSEGV.unwrap() }
    } else {
        assert_eq!(signum, libc::SIGBUS);
        unsafe { OLDACTBUS.unwrap() }
    };
    if !oa.mask().contains(Signal::try_from(signum).unwrap()) {
        match oa.handler() {
            SigHandler::SigDfl => {
                panic_syserr!(libc::kill(libc::getpid(), libc::SIGABRT));
            }
            SigHandler::SigIgn => (),
            SigHandler::Handler(f) => f(signum),
            SigHandler::SigAction(f) => f(signum, info, ucontext),
        }
    }
}

pub type MemoryViolationHandler = fn(addr: *const Void, extend: bool) -> bool;
static mut MEMORY_VIOLATION_HANDLER: Option<MemoryViolationHandler> = None;

pub unsafe fn initialize_memory_violation_handler(h: MemoryViolationHandler) {
    assert_eq!(unsafe { OLDACTSEGV }, None);
    assert_eq!(unsafe { OLDACTBUS }, None);
    let act = SigAction::new(
        SigHandler::SigAction(sighandler),
        SaFlags::SA_RESTART.union(SaFlags::SA_SIGINFO),
        SigSet::empty(),
    );
    unsafe {
        MEMORY_VIOLATION_HANDLER = Some(h);
    }
    unsafe {
        OLDACTBUS = Some(sigaction(Signal::SIGBUS, &act).unwrap());
    }
    unsafe {
        OLDACTSEGV = Some(sigaction(Signal::SIGSEGV, &act).unwrap());
    }
}

fn finalise_sig(s: Signal, osa: &mut Option<SigAction>) {
    unsafe {
        sigaction(s, &osa.unwrap()).unwrap();
        *osa = None;
    }
}

pub unsafe fn finalize_memory_violation_handler() {
    finalise_sig(Signal::SIGSEGV, &mut unsafe { OLDACTSEGV });
    finalise_sig(Signal::SIGBUS, &mut unsafe { OLDACTBUS });
}
