use std::alloc::Allocator as AllocatorTrait;
use super::*;
use const_str;
use indoc;
use std::process::Command;
use std::vec::Vec;
use test_binary::build_test_binary;
use std::alloc::Layout;

#[test]
fn page_boundary() {
    let _ = std::fs::remove_file("test_page_boundary.odb");
    let _ = std::fs::remove_file("test_page_boundary.log");
    type V = Vec<u64, Allocator>;
    let mut h = unsafe {
        Holder::<V>::open(
            "test_page_boundary",
            None,
            MI,
            0xfedcba9876543210,
            |a| V::new_in(a),
        )
    }
    .unwrap();
    let mut w = h.write();
    const I: usize = 16 * KI;
    w.extend_from_slice(&[0u64; I]);
    for i in 0..I * 8 - 7 {
        let a = unsafe { w.as_mut_ptr().byte_add(i).as_mut() }.unwrap();
        *a = !*a;
    }
    w.commit();
    drop(w);

    let r = h.read();
    assert_eq!(
        *r,
        [vec![0x00ff00ff00ff00ff], vec![0u64; I - 2], vec![0xff00ff00ff00ff00]]
            .concat()
    );

    drop(r);
    drop(h);
    let _ = std::fs::remove_file("test_page_boundary.odb");
    let _ = std::fs::remove_file("test_page_boundary.log");
}

#[test]
fn read_recovery() {
    let _ = std::fs::remove_file("test_read_recovery.odb");
    let _ = std::fs::remove_file("test_read_recovery.log");
    type V = Vec<i64, Allocator>;
#[cfg(target_pointer_width = "64")]
    const ADDRESS: usize = 0x70ffe6f00000;
#[cfg(target_pointer_width = "32")]
    const ADDRESS: usize = 0xb6f00000;
    let mut h = unsafe {
        Holder::<V>::open(
            "test_read_recovery",
            Some(ADDRESS),
            MI,
            0xfedcba9876543210,
            |a| V::new_in(a.clone()),
        )
    }
    .unwrap();
    let mut w = h.write();
    const VS: i64 = 120 * KI as i64;
    let v: Vec<i64> = (0i64..VS).collect();
    w.extend_from_slice(&v);
    w.commit();
    drop(w);
    assert_eq!(*h.read(), v);

    let test_bin_path = build_test_binary("suicider", "testbins")
        .expect("error building test binary");
    let output = Command::new(test_bin_path)
        .output()
        .expect("failed to execute test binary");
    assert_eq!(
        output.stdout,
        const_str::to_byte_array!(const_str::format!("w: {}\n", 1 - VS))
    );
    assert_eq!(*h.read(), v);

    drop(h);
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
    let mut h = unsafe {
        Holder::<S>::open(
            "test_grow_and_shrink",
            None,
            MI,
            0xfedcba9876543210,
            |a| S {
                onegin: V::new_in(a.clone()),
                tworoads: V::new_in(a.clone()),
                threelittlepigs: V::new_in(a.clone()),
                fourseasons: V::new_in(a.clone()),
            },
        )
    }
    .unwrap();
    let mut w = h.write();
    w.onegin.extend_from_slice(b"My uncle has most honest principles:\n"); //37
    let a1 = w.onegin.as_ptr();
    let l1 = w.onegin.len();
    w.tworoads.extend_from_slice(b"TWO roads diverged in a yellow wood\n"); //36
    let a2 = w.tworoads.as_ptr();
    let l2 = w.tworoads.len();
    w.tworoads.extend_from_slice(b"And sorry I could not travel");
    assert_eq!(a2, w.tworoads.as_ptr());
    w.tworoads.extend_from_slice(b" both\n"); //+34=70
    assert_eq!(a2, w.tworoads.as_ptr());
    w.onegin.extend_from_slice(b"when he was taken gravely ill,\n"); //+31=68
    let a1m = w.onegin.as_ptr();
    assert_ne!(a1, a1m);
    w.commit();
    w.tworoads.truncate(l2);
    w.tworoads.shrink_to_fit();
    w.threelittlepigs.extend_from_slice(b"Why don't you, sit right back\n");//30
    w.threelittlepigs.extend_from_slice(b"And I, I may tell you, a tale\n");//60
    let a3 = w.threelittlepigs.as_ptr();
    assert_eq!(a3, a1);
    w.onegin.truncate(l1);
    w.onegin.shrink_to_fit();
    w.fourseasons.extend_from_slice(b"All four seasons are special");
    let a4 = w.fourseasons.as_ptr();
    assert!(a2 < a4);
    assert_eq!(unsafe { a2.byte_add(64) }, a4);
    assert!(a4 < a1m);
    assert_eq!(unsafe { a4.byte_add(ALLOCATION_QUANTUM) }, a1m);
    w.threelittlepigs.extend_from_slice(indoc::indoc!(
        b"
        A tale of three, little pigs
        And a big, bad, wolfff
        "
    ));
    let a3m = w.threelittlepigs.as_ptr();
    assert_eq!(unsafe { a1m.byte_add(64) }, a3m);

    drop(w);
    drop(h);
    let _ = std::fs::remove_file("test_grow_and_shrink.odb");
    let _ = std::fs::remove_file("test_grow_and_shrink.log");
}

#[test]
#[should_panic]
fn allocator_leak_should_panic() {
    let _ = std::fs::remove_file("allocator_leak.odb");
    let _ = std::fs::remove_file("allocator_leak.log");
    let mut h = unsafe {
        Holder::<()>::open("allocator_leak",
            None,
            8*KI,
            0xfedcba9876567890,
            |_| (),
        )
    }
    .unwrap();
    let _ = std::fs::remove_file("allocator_leak.odb");
    let _ = std::fs::remove_file("allocator_leak.log");
    let w = h.write();
    let a0 = w.allocator();
    if let Ok(l) = Layout::from_size_align(2, 2) {
        let _ = a0.allocate(l);
        let a1 = a0.clone();
        drop(w);
        let _ = a1.allocate(l);
    }
}

