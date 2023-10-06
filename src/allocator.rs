use std::alloc;
use std::ptr;
use libc::c_void;
use intrusive_collections::Bound::Included as IntrusiveIncluded;
use intrusive_collections::{UnsafeRef};
use super::{FreeBlock, HeaderOfHeader, ALLOCATION_QUANTUM, MEM_MAP};
////////////////////////////////////////////////////////////////////////////////
/// Allocator applicable for standard containers to make them persistent
///
/// Create [super::Writer] by [super::Holder::write] in the same thread before 
/// allocation, deallocation and other persistent storage update.
#[derive(Clone)]
pub struct Allocator {
    pub address: usize,
}

impl Allocator {
    pub fn address(&self) -> usize { self.address }
    // Find the applicable memory segment for the given allocator
    fn segment(&self) -> (*const u8, usize) {
        let a = self.address as *const c_void;
        MEM_MAP.with_borrow(|mb| {
            let ta = mb.get(&a).unwrap();
            (a as *const u8, ta.size)
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

// The address and size-address orders (de)allocation.
fn allocate(from_size: (*const u8, usize), layout: alloc::Layout) ->
        std::result::Result<ptr::NonNull<[u8]>, alloc::AllocError> {
    let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
    let h = unsafe{(from_size.0 as *mut HeaderOfHeader).as_mut()}.unwrap();
    let c = h.by_size_address.lower_bound(
                    IntrusiveIncluded(&(s, std::ptr::null::<FreeBlock>())));
    match c.get() {
        None => Err(alloc::AllocError),
        Some(r) => {
            let p = r as *const FreeBlock;
            let rs = r.size;
            FreeBlock::finalize(h, p);
            if rs > s {
                let n = unsafe{ p.byte_add(s) } as *mut FreeBlock;
                FreeBlock::initialize(h, n, rs - s);
            }
            print!("allocated address is {:X}, size {}\n", p as usize, s);
            Ok(ptr::NonNull::slice_from_raw_parts(
                                ptr::NonNull::new(p as *mut u8).unwrap(), s))
        }
    }
}

unsafe fn deallocate(from_size: (*const u8, usize), ptr: ptr::NonNull<u8>,
                     layout: alloc::Layout) {
    let s = layout.size() + layout.padding_needed_for(ALLOCATION_QUANTUM);
    print!("deallocating address is {:X}, size {}\n", ptr.as_ptr() as usize, s);
    assert!(s % ALLOCATION_QUANTUM == 0);
    let h = unsafe{(from_size.0 as *mut HeaderOfHeader).as_mut()}.unwrap();
    let p = ptr.as_ptr() as *const FreeBlock;
    // XXX These cursors point to neighbours, so could be optimized?
    let cu = h.by_address.lower_bound(IntrusiveIncluded(&p));
    let cl = h.by_address.upper_bound(IntrusiveIncluded(&p));
    let ln = match cl.get() { // lower neighbour
        None => None,
        Some(l) => if (l as *const FreeBlock).byte_add(l.size) < p { None }
                    else { Some(l as *const FreeBlock) }
    };
    let un = match cu.get() { // upper neighbour
        None => None,
        Some(u) => if p.byte_add(s) < u as *const FreeBlock { None }
                    else { Some((u as *const FreeBlock, u.size)) }
    };
    match ln {
        None => match un {
            None => FreeBlock::initialize(h, p, s),
            Some((up, us)) => {
                FreeBlock::finalize(h, up as *const FreeBlock);
                FreeBlock::initialize(h, p, s + us);
            }
        },
        Some(lp) => {
            let lr = lp.cast_mut().as_mut().unwrap();
            h.by_size_address.cursor_mut_from_ptr(lp).remove();
            match un {
                None => lr.size += s,
                Some((up, us)) => {
                    FreeBlock::finalize(h, up);
                    lr.size += s + us;
                }
            };
            h.by_size_address.insert(unsafe { UnsafeRef::from_raw(lp) } );
        }
    }
}


