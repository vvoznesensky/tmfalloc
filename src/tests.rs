use super::*;
use fork;
use os_pipe;
use nix;
use std::io::{Read, Write};
use std::vec::Vec;
use indoc;

#[test]
fn page_boundary() {
    let _ = std::fs::remove_file("test_page_boundary.odb");
    let _ = std::fs::remove_file("test_page_boundary.log");
    type V = Vec<u64, Allocator>;
    let mut h = Holder::<V>::new("test_page_boundary", Some(0x70ffefe00000),
            MI, 0xfedcba9876543210, |a| { V::new_in(a) }).unwrap();
    let mut w = h.write();
    const I: usize = 16*KI;
    w.extend_from_slice(&[0u64; I]);
    for i in 0..I * 8 - 7 {
        let a = unsafe{ w.as_mut_ptr().byte_add(i).as_mut() }.unwrap();
        *a = !*a;
    }
    w.commit();
    drop(w);

    let r = h.read();
    assert_eq!(*r, [
        vec![0x00ff00ff00ff00ff],
        vec![0u64; I - 2],
        vec![0xff00ff00ff00ff00]].concat());

    let _ = std::fs::remove_file("test_page_boundary.odb");
    let _ = std::fs::remove_file("test_page_boundary.log");
}

#[test]
fn read_recovery() {
    let _ = std::fs::remove_file("test_read_recovery.odb");
    let _ = std::fs::remove_file("test_read_recovery.log");
    let (mut reader_child, mut writer_parent) = os_pipe::pipe().unwrap();
    let (mut reader_parent, mut writer_child) = os_pipe::pipe().unwrap();
    match fork::fork() {
        Ok(fork::Fork::Parent(_)) => {
            let h = Holder::<u64>::new("test_read_recovery",
                Some(0x70ffefc00000),
                MI, 0xfedcba9876543210, |_| { 0 }).unwrap();
            writer_parent.write_all(b"1").unwrap();
            let mut b: [u8; 1] = [b'0'];
            assert_eq!(reader_parent.read(&mut b).unwrap(), 1);
            assert_eq!(&b, b"1");
            assert_eq!(*h.read(), 0);
        },
        Ok(fork::Fork::Child) => {
            let mut b: [u8; 1] = [b'0'];
            assert_eq!(reader_child.read(&mut b).unwrap(), 1);
            assert_eq!(&b, b"1");
            let mut h = Holder::<u64>::new("test_read_recovery",
                Some(0x70ffefc00000),
                MI, 0xfedcba9876543210, |_| { panic!("Impossible!") }).unwrap();
            let mut w = h.write();
            *w = 1;
            writer_child.write_all(b"1").unwrap();
            nix::sys::signal::kill(nix::unistd::getpid(),
                            Some(nix::sys::signal::Signal::SIGKILL)).unwrap();
        }
        Err(_) => panic!("Cannot spawn child process"),
    }
    let _ = std::fs::remove_file("test_read_recovery.odb");
    let _ = std::fs::remove_file("test_read_recovery.log");
}

#[test]
fn grow_and_shrink() {
    let _ = std::fs::remove_file("test_grow_and_shrink.odb");
    let _ = std::fs::remove_file("test_grow_and_shrink.log");
    type V = Vec<u8, Allocator>;
    struct S {
        onegin: V,
        tworoads: V,
        threelittlepigs: V,
        fourseasons: V,
    }
    let mut h = Holder::<S>::new("test_grow_and_shrink", Some(0x70ffefa00000),
            MI, 0xfedcba9876543210, |a| {
                S {
                    onegin: V::new_in(a.clone()),
                    tworoads: V::new_in(a.clone()),
                    threelittlepigs: V::new_in(a.clone()),
                    fourseasons: V::new_in(a.clone()),
                } }).unwrap();
    let mut w = h.write();
    w.onegin.extend_from_slice(b"My uncle has most honest principles:\n");
    let a1 = w.onegin.as_ptr();
    let l1 = w.onegin.len();
    w.tworoads.extend_from_slice(b"TWO roads diverged in a yellow wood\n");
    let a2 = w.tworoads.as_ptr();
    let l2 = w.tworoads.len();
    w.tworoads.extend_from_slice(b"And sorry I could not travel");
    assert_eq!(a2, w.tworoads.as_ptr());
    w.tworoads.extend_from_slice(b" both\n");
    assert_eq!(a2, w.tworoads.as_ptr());
    w.onegin.extend_from_slice(b"when he was taken gravely ill,\n");
    assert_ne!(a1, w.onegin.as_ptr());
    w.commit();
    w.tworoads.truncate(l2);
    w.tworoads.shrink_to_fit();
    w.threelittlepigs.extend_from_slice(b"Why don't you, sit right back\n");
    let a3 = w.threelittlepigs.as_ptr();
    assert_eq!(a3, a1);
    w.onegin.truncate(l1);
    w.onegin.shrink_to_fit();
    w.fourseasons.extend_from_slice(b"All four seasons are special somehow\n");
    let a4 = w.fourseasons.as_ptr();
    assert!(a2 < a4);
    assert_eq!(unsafe { a2.byte_add(64) }, a4);
    let a1m = w.onegin.as_ptr();
    assert!(a4 < a1m);
    assert_eq!(unsafe { a4.byte_add(64) }, a1m);
    w.threelittlepigs.extend_from_slice(indoc::indoc!(b"
        And I, I may tell you, a tale
        A tale of three, little pigs
        And a big, bad, wolfff
        "));
    let a3m = w.threelittlepigs.as_ptr();
    assert_eq!(unsafe { a1m.byte_add(64) }, a3m);
    let _ = std::fs::remove_file("test_grow_and_shrink.odb");
    let _ = std::fs::remove_file("test_grow_and_shrink.log");
}

