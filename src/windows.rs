// Microsoft Windows family abstractions.
use windows_sys::{Handle, Win32};

pub type File = Handle;
pub type Void = c_void;

macro_rules! result {
    ( $rval:expr ) => { {
        let r = unsafe { $rval };
        if r as isize == -1 { Err(std::io::Error::last_os_error()) }
        else { Ok(r) }
    } }
}

// Panic on file problems.
macro_rules! panic_syserr {
    ( $rval:expr ) => { {
        let rval = unsafe { $rval };
        if rval as isize == -1 {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
        rval as usize
    } }
}

pub fn open(pathname: &String) -> std::io::Result<File> {
    result!(libc::open(pathname.as_ptr() as *const i8,
                                             libc::O_CREAT|libc::O_RDWR, 0o666))
}

pub unsafe fn read(f: File, buf: *mut Void, s: usize) -> usize {
    panic_syserr!(libc::read(f, buf, s))
}

pub fn write_page(f: File, page_no: u32, page: *const Void, page_size: usize) {
    let iovec = [
        libc::iovec{
            iov_base: std::ptr::from_ref(&page_no) as *mut c_void,
            iov_len: 4} ,
        libc::iovec{ iov_base: page as *mut c_void, iov_len: page_size } ];
    panic_syserr!(libc::writev(f, iovec.as_ptr(), 2));
}

pub fn close(f: File) {
    panic_syserr!(libc::close(f));
}

pub fn seek_begin(f: File) {
    panic_syserr!(libc::lseek(f, 0, libc::SEEK_SET));
}

pub fn mmap(f: File, a: *mut Void, size: usize) -> std::io::Result<*mut Void> {
    let mfn = if a.is_null() {0} else {libc::MAP_FIXED_NOREPLACE};
    let fl = libc::MAP_SHARED | mfn;
    result!(libc::mmap(a, size, libc::PROT_READ, fl, f, 0))
}

pub fn munmap(a: *mut Void, s: usize) {
    panic_syserr!(libc::munmap(a, s));
}

pub fn mprotect_rw(a: *mut Void, s: usize) {
    panic_syserr!(libc::mprotect(a, s, libc::PROT_READ|libc::PROT_WRITE));
}

pub fn mprotect_r(a: *mut Void, s: usize) {
    panic_syserr!(libc::mprotect(a, s, libc::PROT_READ));
}

pub fn mprotect_w(a: *mut Void, s: usize) {
    panic_syserr!(libc::mprotect(a, s, libc::PROT_WRITE));
}

// Making log file ready for the next transaction.
pub fn truncate(lfd: File) {
    panic_syserr!(libc::ftruncate(lfd, 0));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
}

pub fn enlarge(fd: File, offset: usize) {
    panic_syserr!(libc::ftruncate(fd, offset as libc::off_t));
}

// Check if the log file is not empty.
// Remember, the log file offset must be at the end of file.
pub fn not_empty(lfd: File) -> bool {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_END)) > 0
}

// File sync
pub fn sync(lfd: File) {
    panic_syserr!(libc::fdatasync(lfd));
}

// Flock the main file.
pub fn flock_w(fd: File) {
    panic_syserr!(libc::flock(fd, libc::LOCK_EX));
}
pub fn flock_r(fd: File) {
    panic_syserr!(libc::flock(fd, libc::LOCK_SH));
}
pub fn unflock(fd: File) {
    panic_syserr!(libc::flock(fd, libc::LOCK_UN));
}

// Sigaction stuff: signal handler, install/remove it on crate load/remove.
static mut OLDACTSEGV: Option<SigAction> = None;
static mut OLDACTBUS: Option<SigAction> = None;

extern "C" fn sighandler(signum: c_int, info: *mut libc::siginfo_t,
                            ucontext: *mut c_void) {
    let addr = unsafe{info.as_ref().unwrap().si_addr()} as *const Void;
    let extend = signum == libc::SIGBUS;
    if unsafe { MEMORY_VIOLATION_HANDLER.unwrap()(addr, extend) } { return };
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
            },
            SigHandler::SigIgn => (),
            SigHandler::Handler(f) => f(signum),
            SigHandler::SigAction(f) => f(signum, info, ucontext),
        }
    }
}

pub type MemoryViolationHandler = fn(addr: *const Void, extend: bool) -> bool;
static mut MEMORY_VIOLATION_HANDLER: Option<MemoryViolationHandler> = None;

pub unsafe fn initialize_memory_violation_handler(h: MemoryViolationHandler) {
    assert_eq!(unsafe{OLDACTSEGV}, None);
    assert_eq!(unsafe{OLDACTBUS}, None);
    let act = SigAction::new(SigHandler::SigAction(sighandler),
               SaFlags::SA_RESTART.union(SaFlags::SA_SIGINFO), SigSet::empty());
    unsafe { MEMORY_VIOLATION_HANDLER = Some(h); }
    unsafe { OLDACTBUS = Some(sigaction(Signal::SIGBUS, &act).unwrap()); }
    unsafe { OLDACTSEGV = Some(sigaction(Signal::SIGSEGV, &act).unwrap()); }
}

fn finalise_sig(s: Signal, osa: &mut Option<SigAction>) {
    unsafe{
        sigaction(s, &osa.unwrap()).unwrap();
        *osa = None;
    }
}

pub unsafe fn finalize_memory_violation_handler() {
    finalise_sig(Signal::SIGSEGV, &mut unsafe{OLDACTSEGV});
    finalise_sig(Signal::SIGBUS, &mut unsafe{OLDACTBUS});
}
