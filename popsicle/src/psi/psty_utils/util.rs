use itertools::Itertools;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{Block, Block512};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};
use crate::cuckoo::{CuckooItem};

fn block512_to_crt(b: Block512, size: usize) -> Vec<u16> {
    let size_b = size/8;
    let b_val = b.prefix(size_b);

    let mut b_128 = [0_u8; 16];
    b_128[..size_b].clone_from_slice(&b_val[..size_b]);

    let q = fancy_garbling::util::primes_with_width(size as u32);
    fancy_garbling::util::crt(u128::from_le_bytes(b_128), &q)
}

// Assumes payloads are up to 64bit long
pub fn mask_payload_crt(
     x: Block512,
     y: Block512,
     size: usize,
 ) -> Block512 {
     let x_crt = block512_to_crt(x, size);
     let y_crt = block512_to_crt(y, size);

     let q = fancy_garbling::util::primes_with_width(size as u32);

     let mut res_crt = Vec::new();
     for i in 0..q.len() {
         res_crt.push((x_crt[i] + y_crt[i]) % q[i]);
     }
     let res = fancy_garbling::util::crt_inv(&res_crt, &q).to_le_bytes();
     let y_bytes = y.prefix(size);
     let mut block = [0 as u8; 64];
     for i in 0..size {
         if i < size/8{
             block[i] = res[i];
         } else {
             block[i] = y_bytes[i];
         }
     }
     Block512::from(block)
 }

 pub fn int_vec_block512(values: Vec<u64>) -> Vec<Block512> {
     values
         .into_iter()
         .map(|item| {
             let value_bytes = item.to_le_bytes();
             let mut res_block = [0_u8; 64];
             res_block[0..8].clone_from_slice(&value_bytes[..8]);
             Block512::from(res_block)
         })
         .collect()
 }

pub fn cuckoo_place_ids<RNG: RngCore + CryptoRng + SeedableRng>(
    cuckoo: &[Option<CuckooItem>],
    rng:  &mut RNG,
) -> Vec<Block> {
    cuckoo
        .iter()
        .map(|opt_item| match opt_item {
            Some(item) => item.entry_with_hindex(),
            None => rng.gen(),
        })
        .collect::<Vec<Block>>()
}

pub fn cuckoo_place_payloads<RNG: RngCore + CryptoRng + SeedableRng>(
    cuckoo: &[Option<CuckooItem>],
    payloads: &[Block512],
    rng:  &mut RNG,
) -> Vec<Block512> {
    cuckoo
       .iter()
       .map(|opt_item| match opt_item {
           Some(item) => payloads[item.input_index],
           None => rng.gen::<Block512>(),
       })
       .collect::<Vec<Block512>>()
}

// Encoding ID's before passing them to GC.
// Note that we are only looking at HASH_SIZE bytes
// of the IDs.
pub fn encode_inputs(
    opprf_ids: &[Block512],
    input_size: usize
) -> Vec<u16> {
    opprf_ids
        .iter()
        .flat_map(|blk| {
            blk.prefix(input_size)
                .iter()
                .flat_map(|byte| (0..8).map(|i| u16::from((byte >> i) & 1_u8)).collect_vec())
        })
        .collect()
}

// Encoding Payloads's before passing them to GC.
// Note that we are only looking at PAYLOAD_SIZE bytes
// of the payloads.
pub fn encode_payloads(
    payload: &[Block512],
    output_size: usize,
    input_size: usize
) -> Vec<u16> {
    let q = &fancy_garbling::util::PRIMES[..output_size];
    payload
        .iter()
        .flat_map(|blk| {
            let b = blk.prefix(input_size);
            let mut b_8 = [0 as u8; 16];
            for i in 0..input_size{
                b_8[i] = b[i];
            }
            fancy_garbling::util::crt(u128::from_le_bytes(b_8), &q)
        })
        .collect()
}


pub fn split_into_megabins<T: Clone>(
    table: Vec<T>,
    megasize: usize
) -> Vec<Vec<T>>{
    table
        .chunks(megasize)
        .map(|x| x.to_vec())
        .collect()
}

//
pub fn flatten_bin_tags(
    bins: &Vec<Vec<Block>>,
    tags: &Vec<Block512>,
)-> Vec<(Block, Block512)>{
     bins
        .clone()
        .into_iter()
        .zip_eq(tags.iter())
        .flat_map(|(bin, t)| {
            // map all the points in a bin to the same tag
            bin.into_iter().map(move |item| (item, *t))
        })
        .collect_vec()
}

pub fn flatten_bins_payloads(
    bins: &Vec<Vec<Block>>,
    elements: &Vec<Vec<Block512>>,
)-> Vec<(Block, Block512)>{

    bins
        .clone()
        .into_iter()
        .zip_eq(elements.iter())
        .flat_map(|(bin, t)| {
            bin.into_iter().zip_eq(t.iter()).map(move |(item, p)| (item, *p))
        })
        .collect_vec()
}

/// Parse files for PSTY Payload computation.
pub fn parse_files(
    id_position: usize,
    payload_position: usize,
    path: &str,
) -> (Vec<Vec<u8>>, Vec<Block512>) {
    let data = File::open(path).unwrap();

    let buffer = BufReader::new(data).lines();

    let mut ids = Vec::new();
    let mut payloads = Vec::new();

    let mut cnt = 0;
    for line in buffer.enumerate() {
        let line_split = line
            .1
            .unwrap()
            .split(',')
            .map(|item| item.to_string())
            .collect::<Vec<String>>();
        if cnt == 0 {
            cnt += 1;
        } else {
            ids.push(
                line_split[id_position]
                    .parse::<u64>()
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
            );
            payloads.push(line_split[payload_position].parse::<u64>().unwrap());
        }
    }
    (ids, int_vec_block512(payloads))
}
