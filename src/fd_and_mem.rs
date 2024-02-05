////////////////////////////////////////////////////////////////////////////////
// Very internal functions that does not know about Arena structure, but
// only manipulates file descriptors/handlers and mapped memory.

#[cfg_attr(unix, path = "unix.rs")]
#[cfg_attr(windows, path = "windows.rs")]
pub mod os;

// Internal rollback.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in Holder and Writer.
pub unsafe fn rollback<const PAGES_WRITABLE: bool>(
    fd: os::File,
    lfd: os::File,
    mem: *mut os::Void,
    page_size: usize,
) {
    os::seek_begin(lfd);
    let mut page_no: u32 = 0; // 0 for suppressing compilation error
    let pgn_ptr = (&mut page_no as *mut u32) as *mut os::Void;
    while read_exactly(lfd, pgn_ptr, 4) == 4 {
        let offset = (page_no as usize) * page_size;
        let addr = mem.byte_add(offset);
        if !PAGES_WRITABLE {
            os::mprotect_rw(addr, page_size);
        }
        read_exactly(lfd, addr, page_size);
        os::mprotect_r(addr, page_size);
    }
    os::sync(fd);
    os::truncate(lfd);
}

// Internal commit.
// Must be called for flock-ed fd in LOCK_EX mode and guaranteed exclusive
// access of mem for this thread among threads that have access to this fd.
// For further use in WriterAccessor.
pub unsafe fn commit(
    fd: os::File, lfd: os::File, mem: *mut os::Void, size: usize
) {
    os::seek_begin(lfd);
    os::mprotect_r(mem, size);
    os::sync(fd);
    os::truncate(lfd);
}

// Read exactly count bytes or end from the file.
unsafe fn read_exactly(
    lfd: os::File,
    buf: *mut os::Void,
    count: usize,
) -> usize {
    let mut s: usize;
    let mut rval: usize = 0;
    let mut c = count;
    while c > 0 && {
        s = os::read(lfd, buf, c);
        s != 0
    } {
        rval += s;
        c -= s;
    }
    rval
}

// Save the page memory to a file
pub unsafe fn save_old_page(
    mem: *const os::Void,
    size: usize,
    log_fd: os::File,
    page_size: usize,
    addr: *const os::Void,
) {
    let offs = addr.byte_add(1).align_offset(page_size) as isize + 1;
    let begin = addr.byte_offset(offs - (page_size) as isize);
    assert_eq!(begin.align_offset(page_size), 0);
    assert!(begin >= mem);
    let pn = begin.byte_offset_from(mem) / (page_size as isize);
    let page_no: u32 = u32::try_from(pn).unwrap();
    assert!(size / page_size > (page_no as usize));
    os::write_page(log_fd, page_no, begin, page_size);
    os::sync(log_fd);
    os::mprotect_rw(begin as *mut os::Void, page_size);
}

// Extend file to allow further writing
const EXTEND_BYTES: usize = 8;

pub unsafe fn extend_file(
    mem: *const os::Void,
    size: usize,
    odb_fd: os::File,
    page_size: usize,
    addr: *const os::Void,
) {
    let past_addr = unsafe { addr.byte_add(EXTEND_BYTES) };
    let offset = past_addr.align_offset(page_size);
    let e = unsafe { past_addr.byte_add(offset) };
    let offset = usize::try_from(unsafe { e.byte_offset_from(mem) }).unwrap();
    assert!(offset <= size);
    os::enlarge(odb_fd, offset);
}

