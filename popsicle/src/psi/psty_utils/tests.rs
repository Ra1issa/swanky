use scuttlebutt::{SemiHonest};
use crate::psty_payload::{Sender, Receiver};

impl SemiHonest for Sender {}
impl SemiHonest for Receiver {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psty_utils::util::int_vec_block512;
    use crate::utils::rand_u64_vec;
    use fancy_garbling::Wire;
    use rand::{prelude::SliceRandom, thread_rng};
    use scuttlebutt::{AesRng, Block512, Channel, SymChannel};
    use std::{
        collections::HashMap,
        convert::TryInto,
        fs::File,
        io::{BufReader, BufWriter, Write},
        net::{TcpListener, TcpStream},
        os::unix::net::UnixStream,
        borrow::Borrow,
    };

    const ITEM_SIZE: usize = 8;

    fn enum_ids_shuffled(n: usize, id_size: usize) -> Vec<Vec<u8>> {
        let mut vec: Vec<u64> = (0..n as u64).collect();
        vec.shuffle(&mut thread_rng());
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let v: Vec<u8> = vec[i].to_le_bytes().iter().take(id_size).cloned().collect();
            ids.push(v);
        }
        ids
    }

    fn weighted_mean_clear(
        ids_client: &[Vec<u8>],
        ids_server: &[Vec<u8>],
        payloads_client: &[Block512],
        payloads_server: &[Block512],
    ) -> u128 {
        let client_len = ids_client.len();
        let server_len = ids_server.len();
        let mut weighted_payload = 0;
        let mut sum_weights = 0;

        let mut sever_elements = HashMap::new();
        for i in 0..server_len {
            let id_server: &[u8] = &ids_server[i];
            let id_server: [u8; 8] = id_server.try_into().unwrap();
            let id_server = u64::from_le_bytes(id_server);
            let server_val = u64::from_le_bytes(payloads_server[i].prefix(8).try_into().unwrap());
            sever_elements.insert(id_server, server_val);
        }

        for i in 0..client_len {
            let id_client: &[u8] = &ids_client[i];
            let id_client: [u8; 8] = id_client.try_into().unwrap();
            let id_client = u64::from_le_bytes(id_client);
            if sever_elements.contains_key(&id_client) {
                // Assumes values are 64 bit long
                let client_val =
                    u64::from_le_bytes(payloads_client[i].prefix(8).try_into().unwrap());
                weighted_payload =
                    weighted_payload + client_val * sever_elements.get(&id_client).unwrap();
                sum_weights = sum_weights + sever_elements.get(&id_client).unwrap();
            }
        }
        weighted_payload as u128 / sum_weights as u128
    }

    #[test]
    fn test_psty_payload() {
        let set_size_sx: usize = 1 << 6;
        let set_size_rx: usize = 1 << 6;

        let weight_max: u64 = 100000;
        let payload_max: u64 = 100000;

        let payload_size: usize = 64;

        let mut rng = AesRng::new();

        let (sender, receiver) = UnixStream::pair().unwrap();

        let sender_inputs = enum_ids_shuffled(set_size_sx, ITEM_SIZE);
        let receiver_inputs = enum_ids_shuffled(set_size_rx, ITEM_SIZE);
        let weights = int_vec_block512(rand_u64_vec(set_size_sx, weight_max, &mut rng));
        let payloads = int_vec_block512(rand_u64_vec(set_size_rx, payload_max, &mut rng));

        let result_in_clear = weighted_mean_clear(
            &receiver_inputs.borrow(),
            &sender_inputs.borrow(),
            &payloads.borrow(),
            &weights.borrow(),
        );

        std::thread::spawn(move || {
            let mut rng = AesRng::new();

            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut psi = Sender::init(&mut channel, &mut rng).unwrap();

            // For small to medium sized sets where batching can occur accross all bins
            let _ = psi
                .full_protocol(&sender_inputs, &weights, payload_size, &mut channel, &mut rng)
                .unwrap();
        });

        let mut rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();
        // For small to medium sized sets where batching can occur accross all bins
        let weighted_mean = psi
            .full_protocol(&receiver_inputs, &payloads, payload_size, &mut channel, &mut rng)
            .unwrap();

        assert_eq!(result_in_clear, weighted_mean);
    }

    pub fn generate_deltas() -> HashMap<u16, Wire> {
        let mut deltas = HashMap::new();
        let mut rng = rand::thread_rng();
        for q in 2..255{
            deltas.insert(q, Wire::rand_delta(&mut rng, q));
        }
        deltas
    }
    // use crate::psty_utils::psty_large;
    #[test]
    fn test_psty_large() {
        let set_size_sx: usize = 4;
        let set_size_rx: usize = 4;

        let weight_max: u64 = 10;
        let payload_max: u64 = 10;
        let megasize = 1;
        let payload_size: usize = 64;

        let mut rng = AesRng::new();

        let sender_inputs = enum_ids_shuffled(set_size_sx, ITEM_SIZE);
        let receiver_inputs = enum_ids_shuffled(set_size_rx, ITEM_SIZE);
        let weights = int_vec_block512(rand_u64_vec(set_size_sx, weight_max, &mut rng));
        let payloads = int_vec_block512(rand_u64_vec(set_size_rx, payload_max, &mut rng));

        let result_in_clear = weighted_mean_clear(
            &receiver_inputs.borrow(),
            &sender_inputs.borrow(),
            &payloads.borrow(),
            &weights.borrow(),
        );
        println!("result_in_clear {:?}", result_in_clear);

        let deltas = generate_deltas();
        let deltas_json = serde_json::to_string(&deltas).unwrap();

        let path_delta = "./.deltas.txt".to_owned();
        let mut file_deltas = File::create(&path_delta).unwrap();
        file_deltas.write(deltas_json.as_bytes()).unwrap();

        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:3000").unwrap();
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let mut channel = SymChannel::new(stream);
                        let mut rng = AesRng::new();

                        let mut psi = Sender::init(&mut channel, &mut rng).unwrap();
                        let _ = psi
                            .full_protocol_large(
                                &sender_inputs,
                                &weights,
                                payload_size,
                                &path_delta,
                                &mut channel,
                                &mut rng,
                            )
                            .unwrap();
                        println!("Done");
                        return;
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }
            }
            drop(listener);
        });
        match TcpStream::connect("127.0.0.1:3000") {
            Ok(stream) => {
                let mut channel = SymChannel::new(stream);
                let mut rng = AesRng::new();
                let mut psi = Receiver::init(&mut channel, &mut rng).unwrap();

                // For large examples where computation should be batched per-megabin instead of accross all bins.
                let weighted_mean = psi
                    .full_protocol_large(
                        &receiver_inputs,
                        &payloads,
                        payload_size,
                        megasize,
                        &mut channel,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(result_in_clear, weighted_mean);
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
            }
        }
    }
}
