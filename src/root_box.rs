use std::ops::Drop
use libc

// flock(2)s the file on creation in LOCK_EX mode, unlocks on dump, provides
// mutable root object during it's lifetime. See Accessor for initialization.
pub struct MutableRootBox<Root> {
    arena: &mut Arena,
}

impl<Root> MutableRootBox<Root> {
    pub fn root(&self) -> &mut Root {
        let ptr = self.arena.addr as *mut Root;
        unsafe { &*ptr }
    }

    // Not public because cannot rollback data load to registers, etc.
    // Need more expertise to figure it out.
    fn rollback(self) {
        for XXX
    }
}

impl<Root> Drop for MutableRootBox<Root> {
    fn drop(&mut self) {
        assert_eq!(self.arena.shared_counter.load(Ordering::SeqCst), 0)
        self.rollback()
        panic_syserr!(libc::flock(arena.fd, libc::LOCK_UN))

    }
}

// flock(2)s the file on creation in LOCK_SH mode, unlocks on dump, provides
// immutable root object during it's lifetime. See Accessor for initialization.
pub struct ImmutableRootBox<Root> {
    arena: &Arena,
}

impl<Root> ImmutableRootBox<Root> {
    fn root(&self) -> &Root {
        let ptr = arena.addr as *const Root;
        unsafe { &*ptr }
    }
}

impl<Root> Drop for ImmutableRootBox<Root> {
    fn drop(&mut self) {
        if arena.shared_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            panic_syserr!(libc::flock(arena.fd, libc::LOCK_UN))
        }
    }
}
