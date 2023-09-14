// Transaction protected arena for memory mapped file storage allocator
use std::libc;
use std::sync::{RwLock, Mutex};
use std::thread;
use std::io::{Result, Error};
use ctor; // For initialization of SEGV handler.

use nix::sys::signal::{
    sigaction, SigAction, SigHandler, SaFlags, SigSet, Signal};

// Panic on file problems. No graceful error handling available on startup.
macro_rules! panic_syserr {
    ( $rval:expr ) => { {
        let rval = $rval;
        if rval == -1 {
            let errno = *libc::__errno_location();
            let se = libc::strerror(errno);
            assert!(errno > 0);
            panic!(concat!("System error #{}: {}"), errno, se);
        }
        rval
    } }
}

////////////////////////////////////////////////////////////////////////////////
// Arena: internal structure to hold all the file and mapping stuff statically.
struct Arena<'a> {
    idx: u8,
    fd: libc::c_int,     // Main file, mapped onto mem.
    log_fd: libc::c_int, // Log file, consists of pairs (u32 page #, page).
    mem: &'a mut[u8],
    readers: Mutex<u32>, // Number of readers to apply and revoke flock once.
    page_size: libc::c_long,
}

// Array to hold optional 256 arenas.
macro_rules! array {
    (@accum (0, $($_es:expr),*) -> ($($body:tt)*))
        => {array!(@as_expr [$($body)*])};
    (@accum (1, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (0, $($es),*) -> ($($body)* $($es,)*))};
    (@accum (2, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (1, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (4, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (2, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (8, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (4, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (16, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (8, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (32, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (16, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (64, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (32, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (128, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (64, $($es,)* $($es),*) -> ($($body)*))};
    (@accum (256, $($es:expr),*) -> ($($body:tt)*))
        => {array!(@accum (128, $($es,)* $($es),*) -> ($($body)*))};

    (@as_expr $e:expr) => {$e};

    [$e:expr; $n:tt] => { array!(@accum ($n, $e) -> ()) };
}

type OA<'a> = Option<Arena<'a>>;
pub static mut arenas: [RwLock::<OA::<'static>>; 256] =
    array![RwLock::<OA::<'static>>>(None); 256];

////////////////////////////////////////////////////////////////////////////////
// ArenaHolder: RAII fixture to initialize the database files and mmapping.
// Create it once in your code for every IDX that you have chosen.
// Do not mess up with the Root type: this crate cannot figure out if the type
// of root object has been changed someway.
pub struct ArenaHolder<const IDX: u8, Root: Default>;

impl<const IDX: u8, Root: Default> ArenaHolder<IDX, Root> {
    pub fn new(file_pfx: &str, arena_address: usize,
                    arena_size: usize, magick: u8) -> std::io::Result<Self> {
        let mut aowg = arenas[IDX].write().unwrap();
        let &mut ao = aowg.deref_mut();
        match ao {
            Some(a) => { panic!("Arena {} already initialized", IDX); },
            None => {
                let result: std::io::Result<Self>;
                let fname = std::format!("{}.obj", file_pfx);
                let fd = libc::open(fname.as_bytes(), libc::O_CREAT);
                if fd != -1 {
                    let lname = std::format!("{}.log", file_pfx);
                    let ld = libc::open(lname.as_bytes(), libc::O_CREAT);
                    if fd != -1 {
                        let aa = arena_address as *mut c_void;
                        let page_size = libc::sysconf(libc::_SC_PAGE_SIZE);
                        assert_ne!(page_size, -1);
                        let addr = libc::mmap(aa, arena_size, PROT_READ,
                            libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED_NOREPLACE,
                            fd, 0);
                        if addr == aa {
                            let s = unsafe{ std::slice::from_raw_parts_mut(
                                        addr as *mut u8, arena_size) };
                            *ao = Arena {
                                idx: IDX,
                                fd: fd,
                                log_fd: ld,
                                mem: s,
                                readers: Mutex::new(0),
                                page_size: page_size,
                            };
                            flock_w(fd);
                            if check_header::<Root>(magick, s, ld) {
                                rollback::<false>(fd, ld, s, page_size);
                            }
                            unflock(fd);
                            return Ok(Self);
                        }
                        libc::close(ld);
                    }
                    libc::close(fd);
                }
                Err(std::io::Error::from_last_error())
            }
        }
    }
    pub fn write() -> WriteAccessor::<> {
        let mut aowg = arenas[IDX].write().unwrap();
        let &mut ao = aowg.deref_mut();
        match ao {
            None => { panic!("Arena {} not initialized", IDX); },
            Some(a) => {
                flock_w(a.fd);
                arenas_write[IDX] = RefCell::new(Some::new(a));
                setsegv::<IDX>(&a.mem);
                WriteAccessor::<IDX, Root> { guard: aowg, }
            }
        }
    }
    pub fn read() -> ReadAccessor {
        let mut aowg = arenas[IDX].read().unwrap();
        let &mut ao = aowg.deref();
        match ao {
            None => { panic!("Arena {} not initialized", IDX); },
            Some(a) => {
                let readers = a.readers.get_mut();
                if readers == 0 { flock_r(a.fd); }
                readers += 1;
                ReadAccessor::<IDX, Root> {}
            }
        }
    }
}

impl<const IDX: u8, Root> Drop for ArenaHolder<IDX, Root> {
    fn drop(&mut self) {
        let mut aowg = arenas[IDX].write().unwrap();
        let &mut ao = aowg.deref_mut();
        match ao {
            Some(a) => {
                let mem = a.mem.try_write().unwrap();
                flock_w(a.fd);
                rollback::<true>(a.fd, a.log_fd, mem, a.page_size);
                unflock(a.fd);
                panic_syserr!(libc::close(a.log_fd));
                panic_syserr!(libc::munmap(
                        mem.first_mut().unwrap(), mem.len()));
                panic_syserr!(libc::close(a.fd));
                ao = None;
            },
            None => panic!("Arena {} double finalization", IDX),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Very internal functions that does not know about Arena structure, but
// only manipulates fds and mapped memory.

// Internal rollback.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in ArenaHolder and WriteAccessor.
fn rollback<const PAGES_WRITABLE: bool>(fd: libc::c_int, lfd: libc::c_int,
            mem: &mut[u8], page_size: libc::c_long) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    let page_no: u32;
    while read_exactly(lfd, &mut page_no, 4) == 4 {
        let offset = page_no * page_size;
        let addr = &mem[offset] as *mut c_void;
        if !PAGES_WRITABLE {
            assert_eq!(addr, libc::mprotect(addr, page_size, libc::PROT_WRITE));
        }
        panic_syserr!(libc::read(lfd, ptr, page_size));
        assert_eq!(addr, libc::mprotect(addr, page_size, libc::PROT_READ));
    }
    sync(fd);
    truncate(lfd);
}

// Internal commit.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in WriteAccessor.
fn commit(fd: libc::c_int, lfd: libc::c_int,
            mem: &mut[u8], page_size: libc::size_t) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    loop {
        let addr = libc::mprotect(mem.first_mut().unwarp(), mem.len(),
                                                                    PROT_READ);
        panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    }
    sync(fd);
    truncate(lfd);
}

// Read exactly count bytes or 0 from the file.
fn read_exactly(lfd: libc::c_int, buf: *mut c_void,
                count: libc::size_t) -> usize {
    let rval: usize = 0;
    let s: i32;
    while count > 0 && (s = panic_syserr!(libc::read(lfd, buf, count))) != 0 {
        rval += s;
        count -= s;
    }
    rval
}

// Making log file ready for the next transaction.
fn truncate(lfd: libc::c_int) {
    panic_syserr!(libc::ftruncate(lfd, 0));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
}

// File sync
fn sync(lfd: libc::c_int) {
    panic_syserr!(libc::fdatasync(lfd));
}

// Flock the main file.
fn flock_w(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_EX));
}
fn flock_r(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_SH));
}
fn unflock(fd: libc::c_int) {
    panic_syserr!(libc::flock(self.fd, libc::LOCK_UN));
}

// Currently the simpliest bump allocator.
fn alloc<const IDX: u8>(mem: &mut[u8], layout: Layout) ->
        Result<NonNull<[u8]>, AllocError> {
    let h = mem.as_ptr() as *mut HeaderOfHeader;
    let max_size = mem.len();
    let na = h.addr.byte_offset(h.current);
    let s = (na as *const u8).align_offset(layout.align()) + layout.size();
    h.current += s;
    if h.current > max_size {
        return Err(AllocError::fmt("Out of MMTS arena #{}", IDX).unwrap())
    } else {
        return Ok(NonNull::slice_from_raw_parts(na, s))
    }
}

unsafe fn dealloc(mem: &mut[u8], ptr: NonNull<u8>, layout: Layout) {}

////////////////////////////////////////////////////////////////////////////////
// SEGV and it's handler memory map
fn setsegv<const IDX: u8>(mem: &[u8]) {
    let b = &mem.first().unwrap();
    let e = &mem.last().unwrap();
    match mem_map {
        None => mem_map = Some(BTreeMap<*c_void, u8>::new()),
        Some(map) => {
            let c = map.upper_bound(Bound::Included(b));
            if let Some((l, (u,))) = c.key_value() {
                assert!(u < b);
                c.move_next();
                if let Some((l, (u,))) = c.key_value() { assert!(e < l); }
            }
        }
    }
    match mem_map {
        None => panic!("Could not happen"),
        Some(map) => {
            map.insert(b, (e, IDX));
        }
    }
}

fn remsegv<const IDX: u8> (mem: &[u8]) {
    match mem_map {
        None => panic!("Write accessor without a piece in mem_map"),
        Some(map) => {
            let b = &mem.first().unwrap();
            let e = &mem.last().unwrap();
            assert_eq!(map.remove(b), (e, IDX));
        }
    }
}

fn save_page(idx: u8, addr: *const u8) {
    let a = &arenas_write[idx].unwrap();
    let offset = addr.align_offset(a.page_size) as isize;
    let begin = addr.byte_offset(offset - a.page_size);
    assert_eq!(begin.align_offset(a.page_size), 0);
    assert!(begin >= a.mem.as_ptr());
    let page_no: u32 = (begin - a.mem.as_ptr()) as usize / a.page_size;
    panic_syserr!(libc::write(a.log_fd, &page_no, 4));
    panic_syserr!(libc::write(a.log_fd, &begin, a.page_size));
    sync(a.log_fd);
    assert_eq!(addr, libc::mprotect(begin, a.page_size, libc::PROT_WRITE));
}

extern "C" fn sighandler(signum: c_int, info: *mut siginfo_t,
                            ucontext: *mut c_void) {
    assert_eq!(signum, libc::SIG_SEGV);
    match mem_map {
        None => panic!("Could not happen"),
        Some(map) => {
            let addr = info.si_addr() as *mut u8;
            let c = map.upper_bound(Bound::Included(addr));
            if let Some((l, (u, idx))) = c.key_value() {
                if u >= addr { save_page(idx, addr); return; }
            }
            let oa = oldact.unwrap();
            if !oa.mask().contains(signum) {
                match oa.handler {
                    SigDfl => libc::kill(libc::getpid(), libc::SIGABRT),
                    SigIgn => break,
                    Handler(f) => f(signum),
                    SigAction(f) => f(signum, info, ucontext),
                }
            }
        }
    }
}

thread_local! {
    static mem_map: Option<BTreeMap<*const c_void, (*const c_void, u8)>> = None;
}

// Sigaction stuff: signal handler, install/remove it on crate load/remove.
static mut oldact: Option<SigAction> = None;

#[ctor::ctor]
fn initialize() {
    assert_eq!(oldact, None);
    let act = SigAction::new(SigHandler::SigAction(sighandler),
               SaFlags::SA_RESTART.union(SaFlags::SA_SIGINFO), SigSet::empty());
    oldact = Some(sigaction(Signal::SEGV, act).unwrap());
}

#[ctor::dtor]
fn finalize() {
    sigaction(Signal::SEGV, oldact.unwrap()).unwrap();
    oldact = None;
}

////////////////////////////////////////////////////////////////////////////////
// Header stored in file
#[repr(C, align(8))]
struct HeaderOfHeader {
    magick: u64,    // To check the file
    current: usize, // Next piece of the bump allocator
}
#[repr(C, align(8))]
struct Header<Root: Default> {
    h: HeaderOfHeader,
    root: Root,     // The root object.
}

// The file must be locked by flock_w and RwLock.write()
fn check_header<Root: Default>(magick: u64, mem: *mut[u8], lfd: c_int) -> bool {
    let ptr = mem as *mut Header<Root>;
    if ptr.magick != magick {
        truncate(lfd);
        *ptr = Header::<Root> {
            h: HeaderOfHeader {
                magick: magick,
                current: std::mem::size_of::<Header<Root>>,
            },
            root: Default::default()
        };
        false
    } else { true }
}

////////////////////////////////////////////////////////////////////////////////
// Read accessor to allow storage concurrent read access.
struct ReadAccessor<'a, const IDX: u8, Root: Default> {
    holder: &'a ArenaHolder<IDX>,
}
impl<const IDX: u8, Root> Deref for ReadAccessor<u8, Root> {
    // type Target: Root;
    fn deref(&self) -> &Root {
        let mut aowg = arenas[IDX].read().unwrap();
        let &mut ao = aowg.deref();
        match ao {
            None => { panic!("Arena {} not initialized", IDX); },
            Some(a) => *(a.mem as *const Header<Root>).root,
        }
    }
}
impl<const IDX: u8, Root> Dump for ReadAccessor<u8, Root> {
    fn dump(&mut self) {
        let mut aowg = arenas[IDX].read().unwrap();
        let &mut ao = aowg.deref();
        match ao {
            None => { panic!("Arena {} not initialized", IDX); },
            Some(a) => {
                let readers = a.readers.get_mut();
                if readers == 1 { unflock(a.fd); }
                readers -= 1;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Write accessor to allow storage exclusive write access.
struct WriteAccessor<'a, const IDX: u8, Root> {
    guard: RwLockWriteGuard<'a, Arena>,
}
impl<const IDX: u8, Root> DerefMut for WriteAccessor<'a, IDX, Root> {
    fn deref_mut() -> &'a mut Root {
        match arenas_write[IDX].borrow().deref_mut() {
            None => panic!("Dereferencing WriteAccessor without arena handler"),
            Some(a) => *(a.mem as *mut Header<Root>).root,
        }
    }
}
impl<const IDX: u8, Root> Drop for WriteAccessor<'_, IDX, Root> {
    fn drop(&mut self) {
        let arwlg = arenas_write[IDX].borrow().deref_mut();
        match arwlg {
            None => panic!("Dropping WriteAccessor without arena handler"),
            Some(a) => {
                rollback::<true>(a.fd, a.log_fd, a.mem, a.page_size);
                remsegv::<IDX>(&a.mem);
                unflock(a.fd);
                arwlg = RefCell::new(None);
            }
        }
    }
}

thread_local!{
    static arenas_write: [
        RefCell<Option<RwLockReadGuard<'static, Arena>>>; 256] =
            [RefCell::new(None); 256];
}

////////////////////////////////////////////////////////////////////////////////
// Allocator applicable for standard containers to make them persistent.
pub struct Allocator<const IDX: u8>;

impl<const ARENA_ID: u8> alloc::Allocator for Allocator<ARENA_ID> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let go = &mut arenas_write[ARENA_ID].borrow_mut();
        match go {
            None => panic!("Arena #{} have no thread's accessor for writing",
                           ARENA_ID),
            Some(mg) => alloc(mg, layout)
        }
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let go = &mut arenas_write[ARENA_ID].borrow_mut();
        match go {
            None => panic!("Arena #{} have no thread's accessor for writing",
                           ARENA_ID),
            Some(mg) => dealloc(mg, ptr, layout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

