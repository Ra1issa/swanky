// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2020 Galois, Inc.
// See LICENSE for licensing information.

use ocelot::svole::{
    wykw::{Receiver, Sender},
    SVoleReceiver, SVoleSender,
};
use scuttlebutt::{channel::track_unix_channel_pair, field::Gf40, AesRng};
use std::time::Instant;

fn get_trials() -> usize {
    if let Ok(n) = std::env::var("N") {
        n.parse().unwrap()
    } else {
        1
    }
}

type VSender = Sender<Gf40>;
type VReceiver = Receiver<Gf40>;

// <FE: FF, VSender: SVoleSender<Msg = FE>, VReceiver: SVoleReceiver<Msg = FE>>
fn run() {
    let (mut sender, mut receiver) = track_unix_channel_pair();
    let handle = std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            let mut cpu_set = nix::sched::CpuSet::new();
            cpu_set.set(1).unwrap();
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
        }
        let mut rng = AesRng::new();
        let start = Instant::now();
        let mut vole = VSender::init(&mut sender, &mut rng).unwrap();
        println!("Send time (init): {:?}", start.elapsed());
        let start = Instant::now();
        let mut count = 0;
        let mut out = Vec::new();
        for _ in 0..get_trials() {
            vole.send_fast(&mut sender, &mut rng, &mut out).unwrap();
            count += out.len();
            criterion::black_box(&out);
        }
        println!("[{}] Send time (extend): {:?}", count, start.elapsed());
        let start = Instant::now();
        vole.duplicate(&mut sender, &mut rng).unwrap();
        println!("Send time (duplicate): {:?}", start.elapsed());
    });
    #[cfg(target_os = "linux")]
    {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(3).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set).unwrap();
    }
    let mut rng = AesRng::new();
    let start = Instant::now();
    let mut vole = VReceiver::init(&mut receiver, &mut rng).unwrap();
    println!("Receive time (init): {:?}", start.elapsed());
    println!(
        "Send communication (init): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (init): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    let mut count = 0;
    let mut out = Vec::new();
    for _ in 0..get_trials() {
        vole.receive(&mut receiver, &mut rng, &mut out).unwrap();
        count += out.len();
        criterion::black_box(&out);
    }
    println!("[{}] Receive time (extend): {:?}", count, start.elapsed());
    println!(
        "Send communication (extend): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (extend): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    receiver.clear();
    let start = Instant::now();
    let _ = vole.duplicate(&mut receiver, &mut rng).unwrap();
    println!("Receive time (duplicate): {:?}", start.elapsed());
    println!(
        "Send communication (duplicate): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receive communication (duplicate): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    handle.join().unwrap();
}

fn main() {
    println!("\nField: F2_40 \n");
    run/*::<Gf40, Sender<Gf40>, Receiver<Gf40>>*/()
}
