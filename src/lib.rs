// Transaction protected arena for memory mapped file storage allocator

#![feature(allocator_api, pointer_byte_offsets, btree_cursors, concat_bytes,
    ptr_from_ref)]

use ctor;
use errno::{errno};
use libc;
use libc::{c_int, c_void};
use nix::sys::signal::{
    sigaction, SigAction, SigHandler, SaFlags, SigSet, Signal};
use std::alloc;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker;
use std::ops;
use std::ptr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, Mutex, Arc};

// Panic on file problems.
macro_rules! panic_syserr {
    ( $rval:expr ) => { {
        let rval = unsafe { $rval };
        if rval as isize == -1 {
            let e = errno();
            panic!("System error #{}: {}", e.0, e);
        }
        rval
    } }
}

////////////////////////////////////////////////////////////////////////////////
// Arena: internal structure to hold all the file and mapping stuff.
struct Arena {
    fd: c_int,     // Main file, mapped onto mem.
    log_fd: c_int, // Log file, consists of pairs (u32 page #, page).
    mem: *mut c_void,
    size: usize,
    readers: Mutex<u32>, // Number of readers to apply and revoke flock once.
    page_size: usize,
}

////////////////////////////////////////////////////////////////////////////////
// Holder: RAII fixture to initialize the database files and mmapping.
// Do not mess up with the Root type: this crate cannot figure out if the type
// of root object has been changed someway.
pub struct Holder<'a, Root: 'a + Default> {
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}

pub enum Error {
    IoError(std::io::Error),
    WrongFileType,
    WrongMajorVersion,
    WrongMagick,
    WrongAddress,
    WrongSize,
}

pub type Result<T> = std::result::Result<T, Error>;

impl<'a, Root: 'a + Default> Holder<'a, Root> {
    pub fn new(file_pfx: &str, arena_address: usize,
                    arena_size: usize, magick: u64) -> Result<Self> {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
        assert!(ps > 0);
        let page_size = ps as usize;
        assert!(page_size.is_power_of_two());
        let fname = std::format!("{}.odb\0", file_pfx);
        let fd = unsafe {
            libc::open(fname.as_ptr() as *const i8, libc::O_CREAT)
        };
        let rval: Option<Result<Self>> = None;
        if fd != -1 {
            let lname = std::format!("{}.log\0", file_pfx);
            let ld = unsafe {
                libc::open(lname.as_ptr() as *const i8, libc::O_CREAT)
            };
            if ld != -1 {
                let aa = arena_address as *mut c_void;
                let addr = unsafe {
                    libc::mmap(aa, arena_size, libc::PROT_READ,
                        libc::MAP_SHARED_VALIDATE|libc::MAP_FIXED_NOREPLACE,
                        fd, 0)
                };
                if addr == aa {
                    let arena = Arena {
                        fd: fd,
                        log_fd: ld,
                        mem: addr,
                        size: arena_size,
                        readers: Mutex::new(0),
                        page_size: page_size,
                    };
                    let arena = Arc::new(RwLock::new(arena));
                    let s = Self { arena: arena, phantom: marker::PhantomData };
                    let r = prepare_header(&s, magick, arena_address,
                                                                    arena_size);
                    if let Ok(()) = r {
                        return Ok(s);
                    }
                }
                unsafe { libc::close(ld); }
            }
            unsafe { libc::close(fd); }
        }
        match rval {
            Some(r) => r,
            None => Err(Error::IoError(std::io::Error::last_os_error()))
        }
    }
    pub fn read(&self) -> Reader::<Root> {
        let guard = self.arena.read().unwrap();
        {
            let mut readers = guard.readers.lock().unwrap();
            if *readers == 0 { flock_r(guard.fd); }
            *readers += 1;
        }
        Reader::<Root> {
            guard: guard,
            arena: Arc::clone(&self.arena),
            phantom: marker::PhantomData,
        }
    }
    fn internal_write<const PAGES_WRITABLE: bool>(&self) ->
            InternalWriter<Root, PAGES_WRITABLE> {
        let guard = self.arena.write().unwrap();
        flock_w(guard.fd);
        let rv = InternalWriter::<Root, PAGES_WRITABLE> {
            guard: guard,
            _arena: Arc::clone(&self.arena),
            phantom: marker::PhantomData,
        };
        rv.setseg();
        rv
    }
    pub fn write(&mut self) -> Writer<Root> { self.internal_write::<true>() }
}

impl Drop for Arena {
    fn drop(&mut self) {
        flock_w(self.fd);
        rollback::<true>(self.fd, self.log_fd, self.mem, self.page_size);
        unflock(self.fd);
        panic_syserr!(libc::close(self.log_fd));
        panic_syserr!(libc::munmap(self.mem, self.size));
        panic_syserr!(libc::close(self.fd));
    }
}

////////////////////////////////////////////////////////////////////////////////
// Very internal functions that does not know about Arena structure, but
// only manipulates fds and mapped memory.

// Internal rollback.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in Holder and Writer.
fn rollback<const PAGES_WRITABLE: bool>(fd: c_int, lfd: c_int,
            mem: *mut c_void, page_size: usize) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    let mut page_no: u32 = 0; // 0 for suppressing compilation error
    let pgn_ptr = (&mut page_no as *mut u32) as *mut c_void;
    while read_exactly(lfd, pgn_ptr, 4)
            == 4 {
        let offset = (page_no as usize) * page_size;
        let addr = unsafe{mem.byte_offset(offset as isize)};
        if !PAGES_WRITABLE {
            panic_syserr!(libc::mprotect(addr, page_size, libc::PROT_WRITE));
        }
        read_exactly(lfd, addr, page_size);
        panic_syserr!(libc::mprotect(addr, page_size, libc::PROT_READ));
    }
    sync(fd);
    truncate(lfd);
}

// Internal commit.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in WriterAccessor.
fn commit(fd: c_int, lfd: c_int, mem: *mut c_void, size: libc::size_t) {
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    panic_syserr!(libc::mprotect(mem, size, libc::PROT_READ));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
    sync(fd);
    truncate(lfd);
}

// Read exactly count bytes or end from the file.
fn read_exactly(lfd: c_int, buf: *mut c_void, count: libc::size_t) -> usize { 
    let mut s: usize;
    let mut rval: usize = 0;
    let mut c = count;
    while c > 0 && {
            s = panic_syserr!(libc::read(lfd, buf, c)) as usize;
            s != 0} {
        rval += s;
        c -= s;
    }
    rval
}

// Making log file ready for the next transaction.
fn truncate(lfd: c_int) {
    panic_syserr!(libc::ftruncate(lfd, 0));
    panic_syserr!(libc::lseek(lfd, 0, libc::SEEK_SET));
}

// File sync
fn sync(lfd: c_int) {
    panic_syserr!(libc::fdatasync(lfd));
}

// Flock the main file.
fn flock_w(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_EX));
}
fn flock_r(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_SH));
}
fn unflock(fd: c_int) {
    panic_syserr!(libc::flock(fd, libc::LOCK_UN));
}

// Currently the simpliest bump allocator.
fn allocate(from_size: (*const u8, usize), layout: alloc::Layout) ->
        std::result::Result<ptr::NonNull<[u8]>, alloc::AllocError> {
    let h = unsafe{(from_size.0 as *mut HeaderOfHeader).as_mut()}.unwrap();
    let na = unsafe{from_size.0.add(h.current)};
    let s = na.align_offset(layout.align()) + layout.size();
    h.current += s;
    if h.current > from_size.1 {
        return Err(alloc::AllocError)
    } else {
        return Ok(ptr::NonNull::slice_from_raw_parts(
                                ptr::NonNull::new(na.cast_mut()).unwrap(), s))
    }
}

unsafe fn deallocate(_from_size: (*const u8, usize), _ptr: ptr::NonNull<u8>,
                     _layout: alloc::Layout) {}

////////////////////////////////////////////////////////////////////////////////
// SEGV and it's handler memory map
impl<Root, const PAGES_WRITABLE: bool>
        InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn setseg(&self) {
        let g = &self.guard;
        let s = g.size;
        let b = g.mem as *const c_void;
        let e = unsafe{b.byte_offset(s as isize)};
        MEM_MAP.with(|m| {
            let mb = m.borrow();
            let mut c = mb.upper_bound(ops::Bound::Included(&b));
            if let Some((l, ta)) = c.key_value() {
                assert!(unsafe{l.byte_offset(ta.size as isize)} <= b);
                c.move_next();
                if let Some((l, _)) = c.key_value() { assert!(*l >= e); }
            }
        });
        MEM_MAP.with(|m| { m.borrow_mut().insert(b, ThreadArena{
            size: s, log_fd: g.log_fd, page_size: g.page_size}); });
    }

    fn remseg(&self) {
        let g = &self.guard;
        let b = g.mem as *const c_void;
        MEM_MAP.with_borrow_mut(|m| {
            let r = m.remove(&b).unwrap();
            assert_eq!(r, ThreadArena{
                    size: g.size, log_fd: g.log_fd, page_size: g.page_size});
        });
    }
}

fn save_old_page(mem: *const c_void, size: usize, log_fd: c_int,
                                        page_size: usize, addr: *const c_void) {
    let offset = addr.align_offset(page_size) as isize;
    let begin = unsafe{ addr.byte_offset(offset - (page_size) as isize) };
    assert_eq!(begin.align_offset(page_size), 0);
    assert!(begin >= mem);
    let pn = unsafe{begin.byte_offset_from(mem)} / (page_size as isize);
    let page_no: u32 = u32::try_from(pn).unwrap();
    assert!(size / page_size > (page_no as usize));
    // XXX use writev
    panic_syserr!(libc::write(log_fd,
            std::ptr::from_ref::<u32>(&page_no) as *const c_void, 4));
    panic_syserr!(libc::write(log_fd, begin, page_size));
    sync(log_fd);
    panic_syserr!(libc::mprotect(begin as *mut c_void, page_size,
                                                            libc::PROT_WRITE));
}

extern "C" fn sighandler(signum: c_int, info: *mut libc::siginfo_t,
                            ucontext: *mut c_void) {
    assert_eq!(signum, libc::SIGSEGV);
    let addr = unsafe{info.as_ref().unwrap().si_addr()} as *const c_void;
    MEM_MAP.with(|m| {
        let mb = m.borrow();
        let c = mb.upper_bound(ops::Bound::Included(&addr));
        if let Some((l, ta)) = c.key_value() {
            if addr < unsafe{l.byte_offset(ta.size as isize)} {
                save_old_page(*l, ta.size, ta.log_fd, ta.page_size, addr);
                return;
            }
        }
    });
    let oa = unsafe { OLDACT.unwrap() };
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

#[derive(PartialEq, Debug)]
struct ThreadArena {
    size: usize,
    log_fd: c_int,
    page_size: usize,
}
thread_local! {
    static MEM_MAP: RefCell<BTreeMap<*const c_void, ThreadArena>> =
        const { RefCell::new(BTreeMap::new()) };
}

// Sigaction stuff: signal handler, install/remove it on crate load/remove.
static mut OLDACT: Option<SigAction> = None;

#[ctor::ctor]
fn initialize() {
    unsafe{ assert_eq!(OLDACT, None); }
    let act = SigAction::new(SigHandler::SigAction(sighandler),
               SaFlags::SA_RESTART.union(SaFlags::SA_SIGINFO), SigSet::empty());
    unsafe { OLDACT = Some(sigaction(Signal::SIGSEGV, &act).unwrap()); }
}

#[ctor::dtor]
fn finalize() {
    unsafe{
        sigaction(Signal::SIGSEGV, &OLDACT.unwrap()).unwrap();
        OLDACT = None;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Header stored in file
#[repr(C, align(8))]
struct HeaderOfHeader {
    filetype: [u8; 8],  // Letters to show the file type "TMFALLOC"
    version: [u8; 8],   // Crate major version
    magick: u64,        // Error prone fixture to check the user types version
    address: usize,     // Base address of mapping to check
    size:    usize,     // Size of mapping to check
    current: usize,     // Next piece of the bump allocator
}
#[repr(C, align(8))]
struct Header<Root: Default> {
    h: HeaderOfHeader,
    root: Root,
}

// Check if the memory map header is ok.
// If empty, then prepare and commit, otherwise rollback.
fn prepare_header<'a, Root: Default>(holder: &Holder::<'a, Root>,
        magick: u64, address: usize, size: usize) -> Result<()> {
    let w = &holder.internal_write::<false>().guard;
    let header_state = header_is_ok_state(magick, address, size)?;
    let ptr = unsafe{(address as *mut Header<Root>).as_mut()}.unwrap();
    match header_state {
        HeaderState::Fine => {} ,
        HeaderState::NeedsToGrow => {
            ptr.h.size = size;
            commit(w.fd, w.log_fd, w.mem, w.size);
        }
        HeaderState::Empty => {
            *ptr = Header::<Root> {
                h: HeaderOfHeader {
                    filetype: FILETYPE.try_into().unwrap(),
                    version: VERSION.try_into().unwrap(),
                    magick: magick,
                    address: address,
                    size: size,
                    current: std::mem::size_of::<Header<Root>>(),
                },
                root: Default::default()
            };
            commit(w.fd, w.log_fd, w.mem, w.size);
        }
    }
    Ok(())
}
const FILETYPE: &[u8] = b"TMFALLOC";
static VERSION: &[u8] = env!("CARGO_PKG_VERSION_MAJOR").as_bytes();
//const VERSION: &'static [u8; 8] = format!("{:>8}",
//    env!("CARGO_PKG_VERSION_MAJOR"));//.try_into::<>().unwrap();
enum HeaderState { Empty, NeedsToGrow, Fine }
fn header_is_ok_state(magick: u64, address: usize,
                        size: usize) -> Result<HeaderState> {
    let ptr = unsafe{(address as *const HeaderOfHeader).as_ref()}.unwrap();
    if ptr.filetype == [0,0,0,0,0,0,0,0] && ptr.magick == 0 && ptr.address == 0
            && ptr.current == 0 {
        Ok(HeaderState::Empty)
    } else if ptr.filetype != FILETYPE {
        Err(Error::WrongFileType)
    } else if ptr.version != VERSION {
        Err(Error::WrongMajorVersion)
    } else if ptr.magick != magick {
        Err(Error::WrongMagick)
    } else if ptr.address != address {
        Err(Error::WrongAddress)
    } else if ptr.size > size {
        Err(Error::WrongSize)
    } else if ptr.size < size {
        Ok(HeaderState::NeedsToGrow)
    } else { Ok(HeaderState::Fine) }
}

////////////////////////////////////////////////////////////////////////////////
// Reader accessor to allow storage concurrent read access.
pub struct Reader<'a, Root: Default> {
    guard: RwLockReadGuard<'a, Arena>,
    arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}
impl<Root: Default> ops::Deref for Reader<'_, Root> {
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe{(self.guard.mem as *const Header<Root>).as_ref()}.unwrap().root
    }
}
impl<Root: Default> Drop for Reader<'_, Root> {
    fn drop(&mut self) {
        let arena = self.arena.read().unwrap();
        let mut readers = arena.readers.lock().unwrap();
        if *readers == 1 { unflock(arena.fd); }
        assert!(*readers > 0);
        *readers -= 1;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Writer accessor to allow storage exclusive write access.
pub struct InternalWriter<'a, Root, const PAGES_WRITABLE: bool> {
    guard: RwLockWriteGuard<'a, Arena>,
    _arena: Arc<RwLock<Arena>>,
    phantom: marker::PhantomData<&'a Root>
}
impl<Root: Default, const PAGES_WRITABLE: bool> ops::Deref
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    type Target = Root;
    fn deref(&self) -> &Root {
        &unsafe{(self.guard.mem as *const Header<Root>).as_ref()}
            .unwrap().root
    }
}
impl<Root: Default, const PAGES_WRITABLE: bool> ops::DerefMut
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn deref_mut(&mut self) -> &mut Root {
        &mut unsafe{(self.guard.mem as *mut Header<Root>).as_mut()}
            .unwrap().root
    }
}
impl<Root, const PAGES_WRITABLE: bool> Drop
        for InternalWriter<'_, Root, PAGES_WRITABLE> {
    fn drop(&mut self) {
        let a = &self.guard;
        let fd = a.fd;
        rollback::<PAGES_WRITABLE>(fd, a.log_fd, a.mem, a.page_size);
        self.remseg();
        unflock(fd);
    }
}

pub type Writer<'a, Root> = InternalWriter<'a, Root, true>;

////////////////////////////////////////////////////////////////////////////////
// Allocator applicable for standard containers to make them persistent.
pub struct Allocator;

impl Allocator {
    fn segment(&self) -> (*const u8, usize) {
        let a = (self as *const Allocator) as *const c_void;
        MEM_MAP.with(|m| {
            let mb = m.borrow();
            let c = mb.upper_bound(ops::Bound::Included(&a));
            match c.key_value() {
                None => panic!("No arena found for address {:X}", a as usize),
                Some((l, ta)) => {
                    assert!(*l < a); // Internal crate error
                    let u = unsafe { l.byte_offset(ta.size as isize) };
                    assert!(a <= u); // May be crate user's failure
                    (*l as *const u8, ta.size as usize)
                }
            }
        })
    }
}

unsafe impl alloc::Allocator for Allocator {
    fn allocate(&self, layout: alloc::Layout) ->
            std::result::Result<ptr::NonNull<[u8]>, alloc::AllocError> {
        allocate(self.segment(), layout)
    }
    unsafe fn deallocate(&self, p: ptr::NonNull<u8>, layout: alloc::Layout) {
        deallocate(self.segment(), p, layout)
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

