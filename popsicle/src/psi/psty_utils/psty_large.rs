// TODO: Sync up the GB/EV when performing the crt_div: the circuit
// is using prime moduli while the div circuit uses PMR.

use crate::{
    psty_payload::{Sender, SenderState, Receiver, ReceiverState, Msg},
    errors::Error,
    psty_utils::{util, circuits},
};
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    CrtGadgets, Fancy,
};

use ocelot::{
    ot::{AlszReceiver as OtReceiver, AlszSender as OtSender},
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AbstractChannel, Block, Block512};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// State of the sender.
#[derive(Serialize, Deserialize)]
pub struct SenderMegabins{
    pub(crate) states: Vec<SenderState>,
    pub nmegabins: usize,
}

/// State of the receiver.
#[derive(Serialize, Deserialize)]
pub struct ReceiverMegabins{
    pub(crate) states: Vec<ReceiverState>,
    pub nmegabins: usize,
}

impl Sender {
    /// PSI with associated payloads for large sized sets. Batched OPPRF + GC computation is performed
    /// on a Megabin instead of the entirety of the hashed data. The number of Megabin is pre-agreed
    /// on during the bucketization. Users have to specify the GC deltas. If the computation is run
    /// in parallel, the deltas must be synced accross threads.
    pub fn full_protocol_large<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let p =  fancy_garbling::util::primes_with_width(payload_size as u32).len() + 1;

        let mut megabins = self
            .bucketize_data_large(table, payloads, payload_size, channel, rng)?;
        let _ = self
            .compute_circuit(p, payload_size, &mut megabins, &path_deltas, channel, rng).unwrap();

        Ok(())
    }

    pub fn bucketize_data_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result< SenderMegabins, Error> {
        let (state, _nbins) =
            self.bucketize_data(table, payloads, payload_size, channel, rng)?;

        // receive cuckoo hash info from sender
        let megasize = channel.read_usize()?;
        let nmegabins = channel.read_usize()?;

        let ts_id: Vec<Vec<Block512>> = util::split_into_megabins(state.opprf_ids, megasize);
        let ts_payload: Vec<Vec<Block512>> = util::split_into_megabins(state.opprf_payloads, megasize);
        let table: Vec<Vec<Vec<Block>>> = util::split_into_megabins(state.table, megasize);
        let payload: Vec<Vec<Vec<Block512>>> = util::split_into_megabins(state.payload, megasize);
        let mut megabins = SenderMegabins{
            states: Vec::new(),
            nmegabins,
        };

        for i in 0..nmegabins{
            let state = SenderState{
                opprf_ids: ts_id[i].to_owned(),
                opprf_payloads: ts_payload[i].to_owned(),
                table: table[i].to_owned(),
                payload: payload[i].to_owned(),
            };
            megabins.states.push(state);
        }

     Ok(megabins)
    }

    /// PSI computation designed sepecifically for large sets. Assumes the bucketization stage
    /// has already been done, bins were seperated into megabins and that deltas for the circuit
    /// were precomputed.
    /// Returns a garbled output over given megabins that the user can open or join with other
    /// threads results using compute_aggregate.
    pub fn compute_circuit<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        p: usize,
        payload_size: usize,
        megabins: &mut SenderMegabins,
        path_deltas: &str,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        (),
        Error,
    > {
        let mut gb =
            Garbler::<C, RNG, OtSender>::new(channel.clone(), RNG::from_seed(rng.gen())).unwrap();
        let _ = gb.load_deltas(path_deltas);

        let nmegabins = megabins.states.len();
        let mut weighted_values = Vec::new();
        let mut sum_weights = Vec::new();
        for i in 0..nmegabins {
            println!("Starting megabin number {} of {}", i + 1, nmegabins);
            let start = SystemTime::now();

            let nbins = megabins.states[i].opprf_ids.len();
            let mut state = &mut megabins.states[i];
            self.send_data(&mut state, nbins, channel, rng)?;

            let (weighted_value, sum_weight) = state.build_and_compute_circuit(&mut gb, p, payload_size/8).unwrap();
            weighted_values.push(weighted_value);
            sum_weights.push(sum_weight);

            println!(
                "Sender :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
        }
        let num = circuits::sum_crt(&mut gb, &weighted_values).unwrap();
        let denom = circuits::sum_crt(&mut gb, &sum_weights).unwrap();
        let weighted_mean = gb.crt_div(&num, &denom).unwrap();

        gb.outputs(&weighted_mean.wires().to_vec()).unwrap();

        Ok(())
    }
}

impl Receiver {
    /// PSI with associated payloads for large sized sets. Batched OPPRF + GC computation is performed
    /// on a Megabin instead of the entirety of the hashed data. The number of Megabin is pre-agreed
    /// on during the bucketization. Users have to specify the GC deltas. If the computation is run
    /// in parallel, the deltas must be synced accross threads.
    pub fn full_protocol_large<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        payload_size: usize,
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<u128, Error> {
        let p =  fancy_garbling::util::primes_with_width(payload_size as u32).len() + 1 ;

        let mut megabins =self.
                bucketize_data_large(table, payloads, megasize, channel, rng)?;
        let weighted_mean =self.
                compute_circuit(p, payload_size, &mut megabins, channel, rng).unwrap();

        Ok(weighted_mean)
    }

    /// For Large sets, bucketizes using Cuckoo Hashing while mapping to Megabins. The Megabin index
    /// is computed from the regular CH index:
    ///            new_bin_id = ch_id % megabin_size; // the bin within the megabin
    ///            megabin_id =  ch_id / megabin_size;
    /// A megabin is a collection of bins, typically specified by the total number of elements that
    /// can be handled at a time (megabin_size).
    pub fn bucketize_data_large<C: AbstractChannel, RNG: RngCore + CryptoRng + SeedableRng>(
        &mut self,
        table: &[Msg],
        payloads: &[Block512],
        megasize: usize,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<ReceiverMegabins, Error> {
        let (table, payload) = self.bucketize_data(table, payloads, channel, rng)?;

        let table = util::split_into_megabins(table, megasize);
        let payload = util::split_into_megabins(payload, megasize);
        let nmegabins = table.len();

        channel.write_usize(megasize)?; // The megabin size is sent out to the sender
        channel.write_usize(nmegabins)?; // The number of megabins is sent out to the sender
        channel.flush()?;

        let mut megabins = ReceiverMegabins{states: Vec::new(),
            nmegabins};

        for i in 0..nmegabins{
            let state = ReceiverState{
                opprf_ids: Vec::new(),
                opprf_payloads: Vec::new(),
                table: table[i].to_owned(),
                payload: payload[i].to_owned(),
            };
            megabins.states.push(state);
        }

     Ok(megabins)
    }

    /// PSI computation designed sepecifically for large sets. Assumes the bucketization stage
    /// has already been done, bins were seperated into megabins and that deltas for the circuit
    /// were precomputed.
    /// Returns a garbled output over given megabins that the user can open or join with other
    /// threads results using compute_aggregate.
    pub fn compute_circuit<
        C: AbstractChannel,
        RNG: RngCore + CryptoRng + SeedableRng<Seed = Block>,
    >(
        &mut self,
        p: usize,
        payload_size: usize,
        megabins: &mut ReceiverMegabins,
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<
        u128,
        Error,
    > {
        let mut ev =
            Evaluator::<C, RNG, OtReceiver>::new(channel.clone(), RNG::from_seed(rng.gen()))
                .unwrap();

        let nmegabins = megabins.states.len();
        let mut weighted_values = Vec::new();
        let mut sum_weights = Vec::new();
        for i in 0..nmegabins {
            println!("Starting megabin number {} of {}", i + 1, nmegabins);
            let start = SystemTime::now();

            let mut state = &mut megabins.states[i];
            self.receive_data(&mut state, channel, rng)?;

            let (weighted_value, sum_weight) = state.build_and_compute_circuit(&mut ev, p, payload_size/8).unwrap();
            weighted_values.push(weighted_value);
            sum_weights.push(sum_weight);

            println!(
                "Sender :: Computation time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
        }
        let num = circuits::sum_crt(&mut ev, &weighted_values).unwrap();
        let denom = circuits::sum_crt(&mut ev, &sum_weights).unwrap();

        let weighted_mean = ev.crt_div(&num, &denom).unwrap();
        let weighted_mean_outs = ev
            .outputs(&weighted_mean.wires().to_vec())
            .unwrap()
            .expect("evaluator should produce outputs");

        let qs = &fancy_garbling::util::PRIMES[..p];
        let weighted_mean = fancy_garbling::util::crt_inv(&weighted_mean_outs, &qs);

        Ok(weighted_mean)
    }
}
