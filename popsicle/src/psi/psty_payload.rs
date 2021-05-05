// -*- mode: rust; -*-
//
// This file is part of `popsicle`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of the Pinkas-Schneider-Tkachenko-Yanai "extended" private
//! set intersection protocol (cf. <https://eprint.iacr.org/2019/241>).

// What’s the difference with the regular psty:
// - Implements PSTY19's protocol for computation on associated payloads with the intersection,
//   currently the regular psty.rs only revelas the payloads associated with the intersection.
// - Extends the protocol to larger sets via megabins. Now a regular machine can handle extra-large sets
// - Factors and splits out the psty protocol more in-order to expose methods to seperate threads and make parallelization simpler

// Assumption::
//
// - The receiver sends out the number of bins, megabins and the size of a megabin to the sender.
// - The receiver’s set is bigger than the senders (otherwise the code, even without this extension, complains)
// - The megabin size is smaller than the larger set.
// - The receiver gets the output of the computation.


use crate::{
    cuckoo::{CuckooHash},
    errors::Error,
    psty_utils::{circuits,util},
    utils,
};
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    CrtBundle, CrtGadgets, Fancy, FancyInput,
};

use itertools::Itertools;
use ocelot::{
    oprf::{KmprtReceiver, KmprtSender},
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};
use std::fmt::Debug;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

const NHASHES: usize = 3;
// How many bytes of the hash to use for the equality tests. This affects
// correctness, with a lower value increasing the likelihood of a false
// positive.
const HASH_SIZE: usize = 4;

// How many bytes to use to determine whether decryption succeeded in the send/recv
// payload methods.

/// The type of values in the sender and receiver's sets.
pub type Msg = Vec<u8>;

/// Private set intersection sender.
pub struct Sender {
    pub(crate) key: Block,
    pub(crate) opprf: KmprtSender,
    pub(crate) opprf_payload: KmprtSender,
}

/// State of the sender.
#[derive(Default)]
pub struct SenderState {
    pub(crate) opprf_ids: Vec<Block512>,
    pub(crate) opprf_payloads: Vec<Block512>,
    pub(crate) table: Vec<Vec<Block>>,
    pub(crate) payload: Vec<Vec<Block512>>,
}

/// Private set intersection receiver.
pub struct Receiver {
    pub(crate) key: Block,
    pub(crate) opprf: KmprtReceiver,
    pub(crate) opprf_payload: KmprtReceiver,
}

/// State of the receiver.
#[derive(Default)]
pub struct ReceiverState {
    pub(crate) opprf_ids: Vec<Block512>,
    pub(crate) opprf_payloads: Vec<Block512>,
    pub(crate) table: Vec<Block>,
    pub(crate) payload: Vec<Block512>,
}

impl Sender {
    /// Initialize the PSI sender.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let key = channel.read_block()?;
        let opprf = KmprtSender::init(channel, rng)?;
        let opprf_payload = KmprtSender::init(channel, rng)?;
        Ok(Self {
            key,
            opprf,
            opprf_payload,
        })
    }

    /// PSI with associated payloads for small to moderately sized sets without any
    /// parallelization features.
    pub fn full_protocol<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let p =  fancy_garbling::util::primes_with_width(payload_size as u32).len() + 1 ;

        let mut gb =
            Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();

        let (mut state, nbins) = self.bucketize_data(table, payloads, payload_size, channel, rng)?;

        channel.flush()?;
        self.send_data(&mut state, nbins, channel, rng)?;
        channel.flush()?;

        let (aggregate, sum_weights) = state.build_and_compute_circuit(&mut gb, p, payload_size/8).unwrap();
        let weighted_mean = gb.crt_div(&aggregate, &sum_weights).unwrap();

        gb.outputs(&weighted_mean.wires().to_vec()).unwrap();
        channel.flush()?;

        Ok(())
    }

    /// Bucketizes data according to the number of bins specified by the Receiver
    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(SenderState, usize), Error> {
        // receive cuckoo hash info from sender
        let nbins = channel.read_usize()?;
        let hashes = utils::compress_and_hash_inputs(inputs, self.key);

        let mut table = vec![Vec::new(); nbins];
        let mut payload = vec![Vec::new(); nbins];

        let ts_id = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();
        let ts_payload = (0..nbins).map(|_| rng.gen::<Block512>()).collect_vec();

        for (x, p) in hashes.iter().zip_eq(payloads.iter()) {
            let mut bins = Vec::with_capacity(NHASHES);
            for h in 0..NHASHES {
                let bin = CuckooHash::bin(*x, h, nbins);
                table[bin].push(*x ^ Block::from(h as u128));
                // In the case of a binary representation: the payload can be simply XORed
                // with the target vector.
                payload[bin].push(util::mask_payload_crt(*p, ts_payload[bin], payload_size));
                bins.push(bin);
            }
            // if j = H1(y) = H2(y) for some y, then P2 adds a uniformly random element to
            // table2[j] & payload[j]
            if bins.iter().skip(1).all(|&x| x == bins[0]) {
                table[bins[0]].push(rng.gen());
                payload[bins[0]].push(rng.gen());
            }
        }

        let state = SenderState {
            opprf_ids: ts_id,
            opprf_payloads: ts_payload,
            table,
            payload,
        };

        Ok((state, nbins))
    }

    /// Perform OPPRF on ID's & associated payloads
    pub fn send_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state: &mut SenderState,
        nbins: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let points_id = util::flatten_bin_tags(&state.table, &state.opprf_ids);
        let points_data = util::flatten_bins_payloads(&state.table, &state.payload);

        self.opprf.send(channel, &points_id, nbins, rng)?;
        self.opprf_payload.send(channel, &points_data, nbins, rng)?;
        Ok(())
    }
}
//
impl SenderState {
    pub fn garbler_encode_ids<F: FancyInput<Item=W, Error=E>, W: Debug, E: Debug>(
        &mut self,
        gb: &mut F,
    )-> Result<(Vec<W>, Vec<W>), Error>
    {
        let my_input_bits = util::encode_inputs(&self.opprf_ids, HASH_SIZE);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = gb.encode_many(&my_input_bits, &mods_bits).unwrap();
        let receiver_inputs = gb.receive_many(&mods_bits).unwrap();

        Ok((
            sender_inputs,
            receiver_inputs,
        ))

    }
    /// Encodes circuit inputs before passing them to GC
    pub fn garbler_encode_payloads<F: FancyInput<Item=W, Error=E>, W: Debug, E: Debug>(
        &mut self,
        gb: &mut F,
        p: usize,
        payload_size: usize,
    ) -> Result<(Vec<W>, Vec<W>, Vec<W>), Error>
    {
        // encode payloads as CRT
        let my_payload_bits = util::encode_payloads(&self.opprf_payloads, p, payload_size);

        let qs = &fancy_garbling::util::PRIMES[..p].to_vec();
        let mut mods_crt = Vec::new();
        for _i in 0..self.opprf_payloads.len() {
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = gb.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_payloads = gb.receive_many(&mods_crt).unwrap();
        let receiver_masks = gb.receive_many(&mods_crt).unwrap();
        Ok((
            sender_payloads,
            receiver_payloads,
            receiver_masks,
        ))
    }

    /// Encode inputs & compute weighted aggregates circuit
    pub fn build_and_compute_circuit<F, W: Debug, E: Debug>(
        &mut self,
        gb: &mut F,
        p: usize,
        payload_size: usize,
    ) -> Result<
        (
            CrtBundle<W>,
            CrtBundle<W>,
        ),
        Error,
    >
    where
        F: fancy_garbling::FancyReveal + Fancy<Item=W, Error=E> + FancyInput<Item=W, Error=E>,
    {
        let (x, y) = self.garbler_encode_ids(gb).unwrap();
        let (x_payload, y_payload, masks) = self.garbler_encode_payloads(gb, p, payload_size).unwrap();

        let (outs, sum_weights) =
            fancy_compute_payload_aggregate(
                gb,
                &x, &y,
                &x_payload, &y_payload, &masks,
                p).unwrap();

        Ok((outs, sum_weights))
    }
}

impl Receiver {
    /// Initialize the PSI receiver.
    pub fn init<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let key = rng.gen();
        channel.write_block(&key)?;
        channel.flush()?;

        let opprf = KmprtReceiver::init(channel, rng)?;
        let opprf_payload = KmprtReceiver::init(channel, rng)?;
        Ok(Self {
            key,
            opprf,
            opprf_payload,
        })
    }

    /// PSI with associated payloads for small to moderately sized sets without any
    /// parallelization features.
    pub fn full_protocol<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u128, Error> {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();
        let p =  fancy_garbling::util::primes_with_width(payload_size as u32).len() + 1 ;
        let qs = &fancy_garbling::util::PRIMES[..p];

        let (table, payload) = self.bucketize_data(table, payloads, channel, rng)?;
        let mut state: ReceiverState = Default::default();
        state.table = table.clone();
        state.payload = payload.clone();

        self.receive_data(&mut state, channel, rng)?;
        let (aggregate, sum_weights) = state.build_and_compute_circuit(&mut ev, p, payload_size/8).unwrap();
        let weighted_mean = ev.crt_div(&aggregate, &sum_weights).unwrap();

        let weighted_mean_outs = ev
            .outputs(&weighted_mean.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");

        let weighted_mean = fancy_garbling::util::crt_inv(&weighted_mean_outs, &qs);
        channel.flush()?;

        Ok(weighted_mean)
    }

    /// For small to moderate sized sets, bucketizes using Cuckoo Hashing
    pub fn bucketize_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        inputs: &[Msg],
        payloads: &[Block512],
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(Vec<Block>, Vec<Block512>), Error> {
        let hashed_inputs = utils::compress_and_hash_inputs(inputs, self.key);
        let cuckoo = CuckooHash::new(&hashed_inputs, NHASHES)?;

        channel.write_usize(cuckoo.nbins)?; // The number of bins is sent out to the sender
        channel.flush()?;

        let table = util::cuckoo_place_ids(&cuckoo.items, rng);
        let payload = util::cuckoo_place_payloads(&cuckoo.items, payloads, rng);

        Ok((table, payload))
    }

    /// Receive outputs of the OPPRF
    pub fn receive_data<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        state: &mut ReceiverState,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        state.opprf_ids = self.opprf.receive(channel, &state.table, rng)?;
        state.opprf_payloads = self.opprf_payload.receive(channel, &state.table, rng)?;
        Ok(())
    }
}

impl ReceiverState {
    /// Encodes circuit inputs before passing them to GC
    pub fn evaluator_encode_ids<F: FancyInput<Item=W, Error=E>, W: Debug, E: Debug>(
        &mut self,
        ev: &mut F,
    ) -> Result<(Vec<W>, Vec<W>), Error>
    {
        let my_input_bits = util::encode_inputs(&self.opprf_ids, HASH_SIZE);

        let mods_bits = vec![2; my_input_bits.len()];
        let sender_inputs = ev.receive_many(&mods_bits).unwrap();
        let receiver_inputs = ev.encode_many(&my_input_bits, &mods_bits).unwrap();
        Ok((
            sender_inputs,
            receiver_inputs,
        ))
    }

    /// Encodes circuit inputs before passing them to GC
    pub fn evaluator_encode_payloads<F: FancyInput<Item=W, Error=E>, W: Debug, E: Debug>(
        &mut self,
        ev: &mut F,
        p: usize,
        payload_size: usize,
    ) -> Result<(Vec<W>, Vec<W>, Vec<W>), Error>
    {
        let my_opprf_output = util::encode_payloads(&self.opprf_payloads, p, payload_size);
        let my_payload_bits = util::encode_payloads(&self.payload, p, payload_size);

        let qs = &fancy_garbling::util::PRIMES[..p].to_vec();
        let mut mods_crt = Vec::new();
        for _i in 0..self.payload.len() {
            mods_crt.append(&mut qs.clone());
        }

        let sender_payloads = ev.receive_many(&mods_crt).unwrap();
        let receiver_payloads = ev.encode_many(&my_payload_bits, &mods_crt).unwrap();
        let receiver_masks = ev.encode_many(&my_opprf_output, &mods_crt).unwrap();
        Ok((
            sender_payloads,
            receiver_payloads,
            receiver_masks,
        ))
    }

    /// Encode inputs & compute weighted aggregates circuit
    pub fn build_and_compute_circuit<F, W: Debug, E: Debug>(
        &mut self,
        ev: &mut F,
        p: usize,
        payload_size: usize,
    ) -> Result<
        (
            CrtBundle<W>,
            CrtBundle<W>,
        ),
        Error,
    >
    where
        F: fancy_garbling::FancyReveal + Fancy<Item=W, Error=E> + FancyInput<Item=W, Error=E>,
    {
        let (x, y) = self.evaluator_encode_ids(ev)?;
        let (x_payload, y_payload, masks) = self.evaluator_encode_payloads(ev, p, payload_size)?;
        let (outs, sum_weights) =
            fancy_compute_payload_aggregate(ev,&x, &y,&x_payload, &y_payload, &masks,p).unwrap();
        Ok((outs, sum_weights))
    }
}


// Encoding ID's before passing them to GC.
// Note that we are only looking at HASH_SIZE bytes
// of the IDs.
fn encode_inputs(opprf_ids: &[Block512]) -> Vec<u16> {
    opprf_ids
        .iter()
        .flat_map(|blk| {
            blk.prefix(HASH_SIZE)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

// Encoding Payloads's before passing them to GC.
// Note that we are only looking at PAYLOAD_SIZE bytes
// of the payloads.
// + similar comment to encode_opprf_payload
fn encode_payloads(payload: &[Block512]) -> Vec<u16> {
    let q = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
    payload
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(PAYLOAD_SIZE);
            let mut b_8 = [0_u8; 16]; // beyond 64 bits padded with 0s
            b_8[..PAYLOAD_SIZE].clone_from_slice(&b[..PAYLOAD_SIZE]);
            fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}

// Encoding OPPRF output associated with the payloads's before passing them to GC.
// Note that we are only looking at PAYLOAD_PRIME_SIZE bytes of the opprf_payload:
// the size we get after masking the payloads with the target vectors as CRT
//
// Assumes payloads are up to 64bit long:
// The padding is not similarly generated to
// the actual data: Notice how the masked data
// is % with the correct modulus, while the
// padded values are 0.
// When swanky starts supporting larger primes,
// the padded value should be random and modded with the
// appropriate prime at its position
fn encode_opprf_payload(opprf_ids: &[Block512]) -> Vec<u16> {
    let q = &fancy_garbling::util::PRIMES[..PAYLOAD_PRIME_SIZE_EXPANDED];
    opprf_ids
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(PAYLOAD_PRIME_SIZE);
            let mut b_8 = [0_u8; 16];
            b_8[..PAYLOAD_SIZE].clone_from_slice(&b[..PAYLOAD_SIZE]);
            fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}

/// Fancy function to compute a weighted average for matching ID's
/// where one party provides the weights and the other
//  the values
fn fancy_compute_payload_aggregate<F: fancy_garbling::FancyReveal + Fancy>(
    f: &mut F,
    sender_inputs: &[F::Item],
    receiver_inputs: &[F::Item],
    sender_payloads: &[F::Item],
    receiver_payloads: &[F::Item],
    receiver_masks: &[F::Item],
    p: usize,
) -> Result<(CrtBundle<F::Item>, CrtBundle<F::Item>), F::Error> {
    assert_eq!(sender_inputs.len(), receiver_inputs.len());
    assert_eq!(sender_payloads.len(), receiver_payloads.len());
    assert_eq!(receiver_payloads.len(), receiver_masks.len());

    let qs = &fancy_garbling::util::PRIMES[..p];
    let q = fancy_garbling::util::product(&qs);


    let eqs = circuits::check_equality(f, sender_inputs, receiver_inputs, HASH_SIZE)?;
    let reconstructed_payload = circuits::unmask(f, sender_payloads, receiver_masks, p)?;
    let weighted_payloads = circuits::weigh(f, &reconstructed_payload, receiver_payloads, p)?;


    assert_eq!(eqs.len(), weighted_payloads.len());

    let mut acc = f.crt_constant_bundle(0, q)?;
    let mut sum_weights = f.crt_constant_bundle(0, q)?;
    for (i, b) in eqs.iter().enumerate() {
        let b_crt = circuits::expand_bit(f, b, p)?;

        let mux = f.crt_mul(&b_crt, &weighted_payloads[i])?;
        acc = f.crt_add(&acc, &mux)?;

        let mux_sum_weights = f.crt_mul(&b_crt, &reconstructed_payload[i])?;
        sum_weights = f.crt_add(&sum_weights, &mux_sum_weights)?;
    }
    Ok((acc, sum_weights))
}
