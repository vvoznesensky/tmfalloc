use std::alloc
use arena::arenas

// Pass this to all containers to be stored as the generic argument A.
pub struct Allocator<const ARENA_ID: u8>;

impl<const ARENA_ID: u8> alloc::Allocator for Allocator<ARENA_ID> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let a = &mut arenas[ARENA_ID]
        assert!(a.fd >= 0, "MMTS arena #{} not initalized", ARENA_ID)
        let s: size_t
        let b = current_bump.load(Ordering::Acquire)
        let na = a.addr.byte_offset(b)
        loop {
            s = (na as *u8).align_offset(layout.align()) + layout.size()
            let n = a.current_bump.compare_and_swap(b, b + s, Ordering::SeqCst)
            if n == b break;
            na = a.addr.byte_offset(b)
        }
        if b + s > a.size {
            return Err(AllocError::fmt("Out of MMTS arena #{}", ARENA_ID).
                       unwrap())
        } else {
            return Ok(NonNull::slice_from_raw_parts(na, s)
        }
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {}
}

