use super::*;
use fork;
use os_pipe;
use nix;
use std::io::{Read, Write};

#[test]
fn page_boundary() {
    let _ = std::fs::remove_file("test_page_boundary.odb");
    let _ = std::fs::remove_file("test_page_boundary.log");
    type V = std::vec::Vec<u64, Allocator>;
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
                Some(0x70ffefd00000),
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
                Some(0x70ffefd00000),
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

