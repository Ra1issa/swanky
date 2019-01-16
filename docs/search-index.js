var N = null;var searchIndex = {};
searchIndex["fancy_garbling"]={"doc":"","items":[[0,"garble","fancy_garbling","Structs and functions for creating, streaming, and evaluating garbled circuits.",N,N],[3,"Garbler","fancy_garbling::garble","Streams garbled circuit ciphertexts through a callback.",N,N],[3,"Evaluator","","Streaming evaluator using a callback to receive ciphertexts as needed.",N,N],[3,"Encoder","","Encode inputs statically.",N,N],[3,"Decoder","","Decode outputs.",N,N],[3,"GarbledCircuit","","Static evaluator for a circuit, created by the `garble` function.",N,N],[4,"Message","","The outputs that can be emitted by a Garbler and consumed by an Evaluator.",N,N],[13,"UnencodedGarblerInput","","Zero wire and delta for one of the garbler's inputs.",0,N],[12,"zero","fancy_garbling::garble::Message","",0,N],[12,"delta","","",0,N],[13,"UnencodedEvaluatorInput","fancy_garbling::garble","Zero wire and delta for one of the evaluator's inputs.",0,N],[12,"zero","fancy_garbling::garble::Message","",0,N],[12,"delta","","",0,N],[13,"GarblerInput","fancy_garbling::garble","Encoded input for one of the garbler's inputs.",0,N],[13,"EvaluatorInput","","Encoded input for one of the evaluator's inputs.",0,N],[13,"Constant","","Constant wire carrying the value.",0,N],[12,"value","fancy_garbling::garble::Message","",0,N],[12,"wire","","",0,N],[13,"GarbledGate","fancy_garbling::garble","Garbled gate emitted by a projection or multiplication.",0,N],[13,"OutputCiphertext","","Output decoding information.",0,N],[4,"GateType","","Type of a gate, input to the Evaluator's recv function.",N,N],[13,"EvaluatorInput","","The Evaluator in 2PC needs to know to do OT for their own inputs. This as input to the recv function means the current gate is an evaluator input.",1,N],[12,"modulus","fancy_garbling::garble::GateType","",1,N],[13,"Other","fancy_garbling::garble","Some other kind of gate that does not require special OT.",1,N],[5,"garble_iter","","Create an iterator over the messages produced by fancy garbling.",N,N],[5,"garble","","Garble a circuit without streaming.",N,N],[5,"bench_garbling","","Run benchmark garbling and streaming on the function. Garbling function is evaluated on another thread.",N,[[["usize"],["gbf"],["evf"]]]],[11,"new","","Create a new garbler.",2,[[["f"]],["garbler"]]],[11,"get_deltas","","Get the deltas, consuming the Garbler.",2,[[["self"]],["hashmap",["u16","wire"]]]],[11,"new","","Create a new Evaluator.",3,[[["f"]],["evaluator"]]],[11,"decode_output","","Decode the output received during the Fancy computation.",3,[[["self"]],["vec",["u16"]]]],[11,"new","","Create a new GarbledCircuit from a vec of garbled gates and constant wires.",4,[[["vec",["garbledgate"]],["hashmap",["wire"]]],["self"]]],[11,"size","","The number of 128 bit ciphertexts and constant wires in the garbled circuit.",4,[[["self"]],["usize"]]],[11,"eval","","Evaluate the garbled circuit.",4,N],[11,"to_bytes","","",4,[[["self"]],["vec",["u8"]]]],[11,"from_bytes","","",4,N],[11,"new","","",5,[[["vec",["wire"]],["vec",["wire"]],["hashmap",["u16","wire"]]],["self"]]],[11,"num_garbler_inputs","","",5,[[["self"]],["usize"]]],[11,"num_evaluator_inputs","","",5,[[["self"]],["usize"]]],[11,"encode_garbler_input","","",5,[[["self"],["u16"],["usize"]],["wire"]]],[11,"encode_evaluator_input","","",5,[[["self"],["u16"],["usize"]],["wire"]]],[11,"encode_garbler_inputs","","",5,N],[11,"encode_evaluator_inputs","","",5,N],[11,"to_bytes","","",5,[[["self"]],["vec",["u8"]]]],[11,"from_bytes","","",5,N],[11,"new","","",6,[[["vec",["vec"]]],["self"]]],[11,"decode","","",6,N],[11,"to_bytes","","",6,[[["self"]],["vec",["u8"]]]],[11,"from_bytes","","",6,N],[6,"GarbledGate","","The ciphertext created by a garbled gate.",N,N],[6,"OutputCiphertext","","Ciphertext created by the garbler for output gates.",N,N],[11,"to_bytes","","",0,[[["self"]],["vec",["u8"]]]],[11,"from_bytes","","",0,N],[0,"wire","fancy_garbling","Low-level operations on wirelabels, the basic building block of garbled circuits.",N,N],[4,"Wire","fancy_garbling::wire","",N,N],[13,"Mod2","","",7,N],[12,"val","fancy_garbling::wire::Wire","",7,N],[13,"ModN","fancy_garbling::wire","",7,N],[12,"q","fancy_garbling::wire::Wire","",7,N],[12,"ds","","",7,N],[5,"wires_to_bytes","fancy_garbling::wire","",N,N],[5,"wires_from_bytes","","",N,N],[11,"digits","","",7,[[["self"]],["vec",["u16"]]]],[11,"from_u128","","",7,[[["u128"],["u16"]],["self"]]],[11,"as_u128","","",7,[[["self"]],["u128"]]],[11,"zero","","",7,[[["u16"]],["self"]]],[11,"set","","",7,[[["self"],["wire"]]]],[11,"set_zero","","",7,[[["self"]]]],[11,"rand_delta","","",7,[[["r"],["u16"]],["self"]]],[11,"color","","",7,[[["self"]],["u16"]]],[11,"plus","","",7,[[["self"],["self"]],["self"]]],[11,"plus_eq","","",7,[[["self"],["wire"]]]],[11,"cmul","","",7,[[["self"],["u16"]],["self"]]],[11,"cmul_eq","","",7,[[["self"],["u16"]]]],[11,"negate","","",7,[[["self"]],["self"]]],[11,"negate_eq","","",7,[[["self"]]]],[11,"minus","","",7,[[["self"],["wire"]],["wire"]]],[11,"minus_eq","","",7,[[["self"],["wire"]]]],[11,"rand","","",7,[[["r"],["u16"]],["wire"]]],[11,"hash","","",7,[[["self"],["u128"]],["u128"]]],[11,"hashback","","",7,[[["self"],["u128"],["u16"]],["wire"]]],[11,"hash2","","",7,[[["self"],["wire"],["u128"]],["u128"]]],[11,"hashback2","","",7,[[["self"],["wire"],["u128"],["u16"]],["wire"]]],[0,"fancy","fancy_garbling","The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.",N,N],[3,"Bundle","fancy_garbling::fancy","A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.",N,N],[8,"HasModulus","","An object that knows its own modulus.",N,N],[10,"modulus","","The modulus of the wire.",8,[[["self"]],["u16"]]],[8,"Fancy","","DSL for the basic computations supported by fancy-garbling.",N,N],[16,"Item","","The underlying wire datatype created by an object implementing `Fancy`.",9,N],[10,"garbler_input","","Create an input for the garbler with modulus `q`.",9,N],[10,"evaluator_input","","Create an input for the evaluator with modulus `q`.",9,N],[10,"constant","","Create a constant `x` with modulus `q`.",9,N],[10,"add","","Add `x` and `y`.",9,N],[10,"sub","","Subtract `x` and `y`.",9,N],[10,"cmul","","Multiply `x` times the constant `c`.",9,N],[10,"mul","","Multiply `x` and `y`.",9,N],[10,"proj","","Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.",9,N],[10,"output","","Process this wire as output.",9,N],[11,"garbler_inputs","","Create `n` garbler inputs with modulus `q`.",9,[[["self"],["u16"],["usize"]],["vec"]]],[11,"evaluator_inputs","","Create `n` evaluator inputs with modulus `q`.",9,[[["self"],["u16"],["usize"]],["vec"]]],[11,"add_many","","Sum up a slice of wires.",9,N],[11,"xor","","Xor is just addition, with the requirement that `x` and `y` are mod 2.",9,N],[11,"negate","","Negate by xoring `x` with `1`.",9,N],[11,"and","","And is just multiplication, with the requirement that `x` and `y` are mod 2.",9,N],[11,"or","","Or uses Demorgan's Rule implemented with multiplication and negation.",9,N],[11,"and_many","","Returns 1 if all wires equal 1.",9,N],[11,"or_many","","Returns 1 if any wire equals 1.",9,N],[11,"mod_change","","Change the modulus of `x` to `to_modulus` using a projection gate.",9,N],[11,"adder","","Binary adder. Returns the result and the carry.",9,N],[11,"mux","","If `b=0` returns `x` else `y`.",9,N],[11,"mux_constant_bits","","If `x=0` return the constant `b1` else return `b2`. Folds constants if possible.",9,N],[11,"outputs","","Output a slice of wires.",9,N],[8,"BundleGadgets","","Extension trait for `Fancy` providing advanced gadgets based on bundles of wires.",N,N],[11,"garbler_input_bundle","","Crate an input bundle for the garbler using moduli `ps`.",10,N],[11,"evaluator_input_bundle","","Crate an input bundle for the evaluator using moduli `ps`.",10,N],[11,"garbler_input_bundle_crt","","Crate an input bundle for the garbler using composite CRT modulus `q`.",10,[[["self"],["u128"]],["bundle"]]],[11,"evaluator_input_bundle_crt","","Crate an input bundle for the evaluator using composite CRT modulus `q`.",10,[[["self"],["u128"]],["bundle"]]],[11,"garbler_input_bundle_binary","","Create an input bundle for the garbler using n base 2 inputs.",10,[[["self"],["usize"]],["bundle"]]],[11,"evaluator_input_bundle_binary","","Create an input bundle for the evaluator using n base 2 inputs.",10,[[["self"],["usize"]],["bundle"]]],[11,"constant_bundle","","Creates a bundle of constant wires using moduli `ps`.",10,N],[11,"constant_bundle_crt","","Creates a bundle of constant wires for the CRT representation of `x` under composite modulus `q`.",10,[[["self"],["u128"],["u128"]],["bundle"]]],[11,"constant_bundle_binary","","Create a constant bundle using base 2 inputs.",10,N],[11,"garbler_input_bundles","","Create `n` garbler input bundles, using moduli `ps`.",10,N],[11,"evaluator_input_bundles","","Create `n` evaluator input bundles, using moduli `ps`.",10,N],[11,"garbler_input_bundles_crt","","Create `n` garbler input bundles, under composite CRT modulus `q`.",10,[[["self"],["u128"],["usize"]],["vec",["bundle"]]]],[11,"evaluator_input_bundles_crt","","Create `n` evaluator input bundles, under composite CRT modulus `q`.",10,[[["self"],["u128"],["usize"]],["vec",["bundle"]]]],[11,"output_bundle","","Output the wires that make up a bundle.",10,[[["self"],["bundle"]]]],[11,"add_bundles","","Add two wire bundles, residue by residue.",10,[[["self"],["bundle"],["bundle"]],["bundle"]]],[11,"sub_bundles","","Subtract two wire bundles, residue by residue.",10,[[["self"],["bundle"],["bundle"]],["bundle"]]],[11,"cmul_bundle","","Multiplies each wire in `x` by the corresponding residue of `c`.",10,[[["self"],["bundle"],["u128"]],["bundle"]]],[11,"mul_bundles","","Multiply `x` with `y`.",10,[[["self"],["bundle"],["bundle"]],["bundle"]]],[11,"cexp_bundle","","Exponentiate `x` by the constant `c`.",10,[[["self"],["bundle"],["u16"]],["bundle"]]],[11,"rem_bundle","","Compute the remainder with respect to modulus `p`.",10,[[["self"],["bundle"],["u16"]],["bundle"]]],[11,"eq_bundles","","Compute `x == y`. Returns a wire encoding the result mod 2.",10,N],[11,"mixed_radix_addition","","Mixed radix addition.",10,N],[11,"fractional_mixed_radix","","Helper function for advanced gadgets, returns the fractional part of `X/M` where `M=product(ms)`.",10,N],[11,"relu","","Compute `max(x,0)`, using potentially approximate factors of `M`.",10,N],[11,"exact_relu","","Compute `max(x,0)`.",10,[[["self"],["bundle"]],["bundle"]]],[11,"sign","","Return 0 if `x` is positive and 1 if `x` is negative. Potentially approximate depending on `factors_of_m`.",10,N],[11,"exact_sign","","Return 0 if `x` is positive and 1 if `x` is negative.",10,N],[11,"sgn","","Return `if x >= 0 then 1 else -1`, where `-1` is interpreted as `Q-1`. Potentially approximate depending on `factors_of_m`.",10,N],[11,"exact_sgn","","Return `if x >= 0 then 1 else -1`, where `-1` is interpreted as `Q-1`.",10,[[["self"],["bundle"]],["bundle"]]],[11,"exact_lt","","Returns 1 if `x < y`. Works on both CRT and binary bundles.",10,N],[11,"exact_geq","","Returns 1 if `x >= y`. Works on both CRT and binary bundles.",10,N],[11,"max","","Compute the maximum bundle in `xs`. Works on both CRT and binary bundles.",10,N],[11,"binary_addition","","Binary addition. Returns the result and the carry.",10,N],[11,"binary_addition_no_carry","","Binary addition. Avoids creating extra gates for the final carry.",10,[[["self"],["bundle"],["bundle"]],["bundle"]]],[11,"twos_complement","","Compute the twos complement of the input bundle (which must be base 2).",10,[[["self"],["bundle"]],["bundle"]]],[11,"binary_subtraction","","Subtract two binary bundles. Returns the result and whether it overflowed.",10,N],[11,"multiplex","","",10,N],[11,"multiplex_constant_bits","","If `x=0` return `c1` as a bundle of constant bits, else return `c2`.",10,N],[11,"shift","","Shift residues, replacing them with zeros in the modulus of the last residue.",10,[[["self"],["bundle"],["usize"]],["bundle"]]],[11,"binary_cmul","","Write the constant in binary and that gives you the shift amounts, Eg.. 7x is 4x+2x+x.",10,[[["self"],["bundle"],["u128"],["usize"]],["bundle"]]],[11,"abs","","Compute the absolute value of a binary bundle.",10,[[["self"],["bundle"]],["bundle"]]],[11,"new","","Create a new bundle from some wires.",11,[[["vec"]],["bundle"]]],[11,"moduli","","Return the moduli of all the wires in the bundle.",11,[[["self"]],["vec",["u16"]]]],[11,"wires","","Extract the wires from this bundle.",11,N],[11,"size","","Get the number of wires in this bundle.",11,[[["self"]],["usize"]]],[11,"is_binary","","Whether this bundle only contains residues in mod 2.",11,[[["self"]],["bool"]]],[0,"dummy","fancy_garbling","Dummy implementation of Fancy.",N,N],[3,"Dummy","fancy_garbling::dummy","Simple struct that performs the fancy computation over u16.",N,N],[3,"DummyVal","","Wrapper around u16.",N,N],[11,"new","","Create a new Dummy.",12,N],[11,"get_output","","Get the output from the fancy computation, consuming the Dummy.",12,[[["self"]],["vec",["u16"]]]],[0,"informer","fancy_garbling","Informer runs a fancy computation and learns information from it, like how many of what kind of inputs there are.",N,N],[3,"Informer","fancy_garbling::informer","Implements Fancy. Use to learn information about a fancy computation in a lightweight way.",N,N],[3,"InformerVal","","",N,N],[11,"new","","",13,[[],["informer"]]],[11,"print_info","","Print information about the fancy computation.",13,[[["self"]]]],[11,"num_garbler_inputs","","Number of garbler inputs in the fancy computation.",13,[[["self"]],["usize"]]],[11,"garbler_input_moduli","","Moduli of garbler inputs in the fancy computation.",13,[[["self"]],["vec",["u16"]]]],[11,"num_evaluator_inputs","","Number of evaluator inputs in the fancy computation.",13,[[["self"]],["usize"]]],[11,"evaluator_input_moduli","","Moduli of evaluator inputs in the fancy computation.",13,[[["self"]],["vec",["u16"]]]],[11,"num_consts","","Number of constants in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_outputs","","Number of outputs in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_output_ciphertexts","","Number of output ciphertexts.",13,[[["self"]],["usize"]]],[11,"num_adds","","Number of additions in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_subs","","Number of subtractions in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_cmuls","","Number of scalar multiplications in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_muls","","Number of multiplications in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_projs","","Number of projections in the fancy computation.",13,[[["self"]],["usize"]]],[11,"num_ciphertexts","","Number of ciphertexts in the fancy computation.",13,[[["self"]],["usize"]]],[0,"circuit","fancy_garbling","DSL for creating circuits compatible with fancy-garbling in the old-fashioned way, where you create a circuit for a computation then garble it.",N,N],[3,"CircuitRef","fancy_garbling::circuit","The index and modulus of a gate in a circuit.",N,N],[12,"ix","","",14,N],[3,"Circuit","","Static representation of the type of computation supported by fancy garbling.",N,N],[12,"gates","","",15,N],[12,"gate_moduli","","",15,N],[12,"garbler_input_refs","","",15,N],[12,"evaluator_input_refs","","",15,N],[12,"const_refs","","",15,N],[12,"output_refs","","",15,N],[12,"num_nonfree_gates","","",15,N],[3,"CircuitBuilder","","CircuitBuilder is used to build circuits.",N,N],[4,"Gate","","The most basic types of computation supported by fancy garbling.",N,N],[13,"GarblerInput","","",16,N],[12,"id","fancy_garbling::circuit::Gate","",16,N],[13,"EvaluatorInput","fancy_garbling::circuit","",16,N],[12,"id","fancy_garbling::circuit::Gate","",16,N],[13,"Constant","fancy_garbling::circuit","",16,N],[12,"val","fancy_garbling::circuit::Gate","",16,N],[13,"Add","fancy_garbling::circuit","",16,N],[12,"xref","fancy_garbling::circuit::Gate","",16,N],[12,"yref","","",16,N],[13,"Sub","fancy_garbling::circuit","",16,N],[12,"xref","fancy_garbling::circuit::Gate","",16,N],[12,"yref","","",16,N],[13,"Cmul","fancy_garbling::circuit","",16,N],[12,"xref","fancy_garbling::circuit::Gate","",16,N],[12,"c","","",16,N],[13,"Mul","fancy_garbling::circuit","",16,N],[12,"xref","fancy_garbling::circuit::Gate","",16,N],[12,"yref","","",16,N],[12,"id","","",16,N],[13,"Proj","fancy_garbling::circuit","",16,N],[12,"xref","fancy_garbling::circuit::Gate","",16,N],[12,"tt","","",16,N],[12,"id","","",16,N],[11,"eval","fancy_garbling::circuit","",15,N],[11,"num_garbler_inputs","","",15,[[["self"]],["usize"]]],[11,"num_evaluator_inputs","","",15,[[["self"]],["usize"]]],[11,"noutputs","","",15,[[["self"]],["usize"]]],[11,"modulus","","",15,[[["self"],["usize"]],["u16"]]],[11,"garbler_input_mod","","",15,[[["self"],["usize"]],["u16"]]],[11,"evaluator_input_mod","","",15,[[["self"],["usize"]],["u16"]]],[11,"print_info","","",15,[[["self"]]]],[11,"to_file","","",15,[[["self"],["str"]],["result",["error"]]]],[11,"from_file","","",15,[[["str"]],["result",["circuit","error"]]]],[11,"to_string","","",15,[[["self"]],["string"]]],[11,"from_str","","",15,[[["str"]],["result",["circuit","error"]]]],[11,"new","","",17,[[],["self"]]],[11,"finish","","",17,[[["self"]],["circuit"]]],[0,"util","fancy_garbling","Tools useful for interacting with `fancy-garbling`.",N,N],[5,"tweak","fancy_garbling::util","Tweak function for a single item.",N,[[["usize"]],["u128"]]],[5,"tweak2","","Tweak function for two items.",N,[[["u64"],["u64"]],["u128"]]],[5,"output_tweak","","Compute the output tweak for a garbled gate where i is the gate id and k is the value.",N,[[["usize"],["u16"]],["u128"]]],[5,"base_q_add","","Add two base q numbers together.",N,N],[5,"base_q_add_eq","","Add a base q number into the first one.",N,N],[5,"as_base_q","","Convert a u128 into base q.",N,[[["u128"],["u16"],["usize"]],["vec",["u16"]]]],[5,"digits_per_u128","","Determine how many mod q digits fit into a u128.",N,[[["u16"]],["usize"]]],[5,"as_base_q_u128","","Convert a u128 into base q.",N,[[["u128"],["u16"]],["vec",["u16"]]]],[5,"as_mixed_radix","","Convert a u128 into mixed radix form with the provided radii.",N,N],[5,"from_base_q","","Convert little-endian base q digits into u128.",N,N],[5,"from_mixed_radix","","Convert little-endian mixed radix digits into u128.",N,N],[5,"u128_to_bits","","Get the bits of a u128 encoded in 128 u16s, which is convenient for the rest of the library, which uses u16 as the base digit type in Wire.",N,[[["u128"],["usize"]],["vec",["u16"]]]],[5,"u128_from_bits","","Convert into a u128 from the \"bits\" as u16. Assumes each \"bit\" is 0 or 1.",N,N],[5,"u128_to_bytes","","Convert a u128 into bytes.",N,N],[5,"bytes_to_u128","","Convert bytes to u128.",N,N],[5,"factor","","Factor using the primes in the global `PRIMES` array. Fancy garbling only supports composites with small prime factors.",N,[[["u128"]],["vec",["u16"]]]],[5,"crt","","Compute the CRT representation of x with respect to the primes ps.",N,N],[5,"crt_factor","","Compute the CRT representation of x with respect to the factorization of q.",N,[[["u128"],["u128"]],["vec",["u16"]]]],[5,"crt_inv","","Compute the value x given a list of CRT primes and residues.",N,N],[5,"crt_inv_factor","","Compute the value x given a composite CRT modulus.",N,N],[5,"inv_ref","","Generic algorithm to invert inp_a mod inp_b. As ref so as to support BigInts without copying.",N,[[["t"],["t"]],["t"]]],[5,"inv","","Invert a mod m.",N,[[["t"],["t"]],["t"]]],[5,"modulus_with_width","","Generate a CRT modulus that support at least n-bit integers, using the built-in PRIMES.",N,[[["u32"]],["u128"]]],[5,"primes_with_width","","Generate the factors of a CRT modulus that support at least n-bit integers, using the built-in PRIMES.",N,[[["u32"]],["vec",["u16"]]]],[5,"base_modulus_with_width","","Generate a CRT modulus that support at least n-bit integers, using provided primes.",N,N],[5,"base_primes_with_width","","Generate the factors of a CRT modulus that support at least n-bit integers, using provided primes.",N,N],[5,"modulus_with_width_skip2","","Generate a CRT modulus that support at least n-bit integers, using the built-in PRIMES_SKIP_2 (does not include 2 as a factor).",N,[[["u32"]],["u128"]]],[5,"product","","Compute the product of some u16s as a u128.",N,N],[5,"powm","","Raise a u16 to a power mod some value.",N,[[["u16"],["u16"],["u16"]],["u16"]]],[5,"is_power_of_2","","Returns true if x is a power of 2. Delightfully generic.",N,[[["i"]],["bool"]]],[17,"NPRIMES","","Number of primes supported by our library.",N,N],[17,"PRIMES","","Primes used in fancy garbling.",N,N],[17,"PRIMES_SKIP_2","","Primes skipping the modulus 2, which allows certain gadgets.",N,N],[8,"RngExt","","Extra Rng functionality, useful for `fancy-garbling`.",N,N],[11,"gen_bool","","",18,[[["self"]],["bool"]]],[11,"gen_u16","","",18,[[["self"]],["u16"]]],[11,"gen_u32","","",18,[[["self"]],["u32"]]],[11,"gen_u64","","",18,[[["self"]],["u16"]]],[11,"gen_usize","","",18,[[["self"]],["usize"]]],[11,"gen_u128","","",18,[[["self"]],["u128"]]],[11,"gen_usable_u128","","",18,[[["self"],["u16"]],["u128"]]],[11,"gen_prime","","",18,[[["self"]],["u16"]]],[11,"gen_modulus","","",18,[[["self"]],["u16"]]],[11,"gen_usable_composite_modulus","","",18,[[["self"]],["u128"]]],[11,"gen_usable_factors","","",18,[[["self"]],["vec",["u16"]]]],[11,"into","fancy_garbling::garble","",2,[[["self"]],["u"]]],[11,"from","","",2,[[["t"]],["t"]]],[11,"try_from","","",2,[[["u"]],["result"]]],[11,"borrow","","",2,[[["self"]],["t"]]],[11,"get_type_id","","",2,[[["self"]],["typeid"]]],[11,"try_into","","",2,[[["self"]],["result"]]],[11,"borrow_mut","","",2,[[["self"]],["t"]]],[11,"into","","",3,[[["self"]],["u"]]],[11,"from","","",3,[[["t"]],["t"]]],[11,"try_from","","",3,[[["u"]],["result"]]],[11,"borrow","","",3,[[["self"]],["t"]]],[11,"get_type_id","","",3,[[["self"]],["typeid"]]],[11,"try_into","","",3,[[["self"]],["result"]]],[11,"borrow_mut","","",3,[[["self"]],["t"]]],[11,"into","","",5,[[["self"]],["u"]]],[11,"from","","",5,[[["t"]],["t"]]],[11,"try_from","","",5,[[["u"]],["result"]]],[11,"borrow","","",5,[[["self"]],["t"]]],[11,"get_type_id","","",5,[[["self"]],["typeid"]]],[11,"try_into","","",5,[[["self"]],["result"]]],[11,"borrow_mut","","",5,[[["self"]],["t"]]],[11,"into","","",6,[[["self"]],["u"]]],[11,"from","","",6,[[["t"]],["t"]]],[11,"try_from","","",6,[[["u"]],["result"]]],[11,"borrow","","",6,[[["self"]],["t"]]],[11,"get_type_id","","",6,[[["self"]],["typeid"]]],[11,"try_into","","",6,[[["self"]],["result"]]],[11,"borrow_mut","","",6,[[["self"]],["t"]]],[11,"into","","",4,[[["self"]],["u"]]],[11,"from","","",4,[[["t"]],["t"]]],[11,"try_from","","",4,[[["u"]],["result"]]],[11,"borrow","","",4,[[["self"]],["t"]]],[11,"get_type_id","","",4,[[["self"]],["typeid"]]],[11,"try_into","","",4,[[["self"]],["result"]]],[11,"borrow_mut","","",4,[[["self"]],["t"]]],[11,"into","","",0,[[["self"]],["u"]]],[11,"to_string","","",0,[[["self"]],["string"]]],[11,"from","","",0,[[["t"]],["t"]]],[11,"try_from","","",0,[[["u"]],["result"]]],[11,"borrow","","",0,[[["self"]],["t"]]],[11,"get_type_id","","",0,[[["self"]],["typeid"]]],[11,"try_into","","",0,[[["self"]],["result"]]],[11,"borrow_mut","","",0,[[["self"]],["t"]]],[11,"into","","",1,[[["self"]],["u"]]],[11,"from","","",1,[[["t"]],["t"]]],[11,"try_from","","",1,[[["u"]],["result"]]],[11,"borrow","","",1,[[["self"]],["t"]]],[11,"get_type_id","","",1,[[["self"]],["typeid"]]],[11,"try_into","","",1,[[["self"]],["result"]]],[11,"borrow_mut","","",1,[[["self"]],["t"]]],[11,"into","fancy_garbling::wire","",7,[[["self"]],["u"]]],[11,"to_owned","","",7,[[["self"]],["t"]]],[11,"clone_into","","",7,N],[11,"from","","",7,[[["t"]],["t"]]],[11,"try_from","","",7,[[["u"]],["result"]]],[11,"borrow","","",7,[[["self"]],["t"]]],[11,"get_type_id","","",7,[[["self"]],["typeid"]]],[11,"try_into","","",7,[[["self"]],["result"]]],[11,"borrow_mut","","",7,[[["self"]],["t"]]],[11,"into","fancy_garbling::fancy","",11,[[["self"]],["u"]]],[11,"to_owned","","",11,[[["self"]],["t"]]],[11,"clone_into","","",11,N],[11,"from","","",11,[[["t"]],["t"]]],[11,"try_from","","",11,[[["u"]],["result"]]],[11,"borrow","","",11,[[["self"]],["t"]]],[11,"get_type_id","","",11,[[["self"]],["typeid"]]],[11,"try_into","","",11,[[["self"]],["result"]]],[11,"borrow_mut","","",11,[[["self"]],["t"]]],[11,"into","fancy_garbling::dummy","",12,[[["self"]],["u"]]],[11,"from","","",12,[[["t"]],["t"]]],[11,"try_from","","",12,[[["u"]],["result"]]],[11,"borrow","","",12,[[["self"]],["t"]]],[11,"get_type_id","","",12,[[["self"]],["typeid"]]],[11,"try_into","","",12,[[["self"]],["result"]]],[11,"borrow_mut","","",12,[[["self"]],["t"]]],[11,"into","","",19,[[["self"]],["u"]]],[11,"to_owned","","",19,[[["self"]],["t"]]],[11,"clone_into","","",19,N],[11,"from","","",19,[[["t"]],["t"]]],[11,"try_from","","",19,[[["u"]],["result"]]],[11,"borrow","","",19,[[["self"]],["t"]]],[11,"get_type_id","","",19,[[["self"]],["typeid"]]],[11,"try_into","","",19,[[["self"]],["result"]]],[11,"borrow_mut","","",19,[[["self"]],["t"]]],[11,"into","fancy_garbling::informer","",13,[[["self"]],["u"]]],[11,"from","","",13,[[["t"]],["t"]]],[11,"try_from","","",13,[[["u"]],["result"]]],[11,"borrow","","",13,[[["self"]],["t"]]],[11,"get_type_id","","",13,[[["self"]],["typeid"]]],[11,"try_into","","",13,[[["self"]],["result"]]],[11,"borrow_mut","","",13,[[["self"]],["t"]]],[11,"into","","",20,[[["self"]],["u"]]],[11,"to_owned","","",20,[[["self"]],["t"]]],[11,"clone_into","","",20,N],[11,"from","","",20,[[["t"]],["t"]]],[11,"try_from","","",20,[[["u"]],["result"]]],[11,"borrow","","",20,[[["self"]],["t"]]],[11,"get_type_id","","",20,[[["self"]],["typeid"]]],[11,"try_into","","",20,[[["self"]],["result"]]],[11,"borrow_mut","","",20,[[["self"]],["t"]]],[11,"into","fancy_garbling::circuit","",14,[[["self"]],["u"]]],[11,"to_owned","","",14,[[["self"]],["t"]]],[11,"clone_into","","",14,N],[11,"from","","",14,[[["t"]],["t"]]],[11,"try_from","","",14,[[["u"]],["result"]]],[11,"borrow","","",14,[[["self"]],["t"]]],[11,"get_type_id","","",14,[[["self"]],["typeid"]]],[11,"try_into","","",14,[[["self"]],["result"]]],[11,"borrow_mut","","",14,[[["self"]],["t"]]],[11,"into","","",15,[[["self"]],["u"]]],[11,"to_owned","","",15,[[["self"]],["t"]]],[11,"clone_into","","",15,N],[11,"from","","",15,[[["t"]],["t"]]],[11,"try_from","","",15,[[["u"]],["result"]]],[11,"borrow","","",15,[[["self"]],["t"]]],[11,"get_type_id","","",15,[[["self"]],["typeid"]]],[11,"try_into","","",15,[[["self"]],["result"]]],[11,"borrow_mut","","",15,[[["self"]],["t"]]],[11,"into","","",17,[[["self"]],["u"]]],[11,"from","","",17,[[["t"]],["t"]]],[11,"try_from","","",17,[[["u"]],["result"]]],[11,"borrow","","",17,[[["self"]],["t"]]],[11,"get_type_id","","",17,[[["self"]],["typeid"]]],[11,"try_into","","",17,[[["self"]],["result"]]],[11,"borrow_mut","","",17,[[["self"]],["t"]]],[11,"into","","",16,[[["self"]],["u"]]],[11,"to_owned","","",16,[[["self"]],["t"]]],[11,"clone_into","","",16,N],[11,"from","","",16,[[["t"]],["t"]]],[11,"try_from","","",16,[[["u"]],["result"]]],[11,"borrow","","",16,[[["self"]],["t"]]],[11,"get_type_id","","",16,[[["self"]],["typeid"]]],[11,"try_into","","",16,[[["self"]],["result"]]],[11,"borrow_mut","","",16,[[["self"]],["t"]]],[11,"modulus","fancy_garbling::wire","",7,[[["self"]],["u16"]]],[11,"modulus","fancy_garbling::dummy","",19,[[["self"]],["u16"]]],[11,"modulus","fancy_garbling::informer","",20,[[["self"]],["u16"]]],[11,"modulus","fancy_garbling::circuit","",14,[[["self"]],["u16"]]],[11,"garbler_input","fancy_garbling::garble","",2,[[["self"],["u16"]],["wire"]]],[11,"evaluator_input","","",2,[[["self"],["u16"]],["wire"]]],[11,"constant","","",2,[[["self"],["u16"],["u16"]],["wire"]]],[11,"add","","",2,[[["self"],["wire"],["wire"]],["wire"]]],[11,"sub","","",2,[[["self"],["wire"],["wire"]],["wire"]]],[11,"cmul","","",2,[[["self"],["wire"],["u16"]],["wire"]]],[11,"mul","","",2,[[["self"],["wire"],["wire"]],["wire"]]],[11,"proj","","",2,N],[11,"output","","",2,[[["self"],["wire"]]]],[11,"garbler_input","","",3,[[["self"],["u16"]],["wire"]]],[11,"evaluator_input","","",3,[[["self"],["u16"]],["wire"]]],[11,"constant","","",3,[[["self"],["u16"],["u16"]],["wire"]]],[11,"add","","",3,[[["self"],["wire"],["wire"]],["wire"]]],[11,"sub","","",3,[[["self"],["wire"],["wire"]],["wire"]]],[11,"cmul","","",3,[[["self"],["wire"],["u16"]],["wire"]]],[11,"mul","","",3,[[["self"],["wire"],["wire"]],["wire"]]],[11,"proj","","",3,N],[11,"output","","",3,[[["self"],["wire"]]]],[11,"garbler_input","fancy_garbling::dummy","",12,[[["self"],["u16"]],["dummyval"]]],[11,"evaluator_input","","",12,[[["self"],["u16"]],["dummyval"]]],[11,"constant","","",12,[[["self"],["u16"],["u16"]],["dummyval"]]],[11,"add","","",12,[[["self"],["dummyval"],["dummyval"]],["dummyval"]]],[11,"sub","","",12,[[["self"],["dummyval"],["dummyval"]],["dummyval"]]],[11,"cmul","","",12,[[["self"],["dummyval"],["u16"]],["dummyval"]]],[11,"mul","","",12,[[["self"],["dummyval"],["dummyval"]],["dummyval"]]],[11,"proj","","",12,N],[11,"output","","",12,[[["self"],["dummyval"]]]],[11,"garbler_input","fancy_garbling::informer","",13,[[["self"],["u16"]],["informerval"]]],[11,"evaluator_input","","",13,[[["self"],["u16"]],["informerval"]]],[11,"constant","","",13,[[["self"],["u16"],["u16"]],["informerval"]]],[11,"add","","",13,[[["self"],["informerval"],["informerval"]],["informerval"]]],[11,"sub","","",13,[[["self"],["informerval"],["informerval"]],["informerval"]]],[11,"cmul","","",13,[[["self"],["informerval"],["u16"]],["informerval"]]],[11,"mul","","",13,[[["self"],["informerval"],["informerval"]],["informerval"]]],[11,"proj","","",13,N],[11,"output","","",13,[[["self"],["informerval"]]]],[11,"garbler_input","fancy_garbling::circuit","",17,[[["self"],["u16"]],["circuitref"]]],[11,"evaluator_input","","",17,[[["self"],["u16"]],["circuitref"]]],[11,"constant","","",17,[[["self"],["u16"],["u16"]],["circuitref"]]],[11,"add","","",17,[[["self"],["circuitref"],["circuitref"]],["circuitref"]]],[11,"sub","","",17,[[["self"],["circuitref"],["circuitref"]],["circuitref"]]],[11,"cmul","","",17,[[["self"],["circuitref"],["u16"]],["circuitref"]]],[11,"proj","","",17,N],[11,"mul","","",17,[[["self"],["circuitref"],["circuitref"]],["circuitref"]]],[11,"output","","",17,[[["self"],["circuitref"]]]],[11,"partial_cmp","fancy_garbling::wire","",7,[[["self"],["wire"]],["option",["ordering"]]]],[11,"lt","","",7,[[["self"],["wire"]],["bool"]]],[11,"le","","",7,[[["self"],["wire"]],["bool"]]],[11,"gt","","",7,[[["self"],["wire"]],["bool"]]],[11,"ge","","",7,[[["self"],["wire"]],["bool"]]],[11,"default","","",7,[[],["wire"]]],[11,"default","fancy_garbling::fancy","",11,[[],["bundle"]]],[11,"default","fancy_garbling::dummy","",19,[[],["dummyval"]]],[11,"default","fancy_garbling::informer","",20,[[],["informerval"]]],[11,"default","fancy_garbling::circuit","",14,[[],["circuitref"]]],[11,"eq","fancy_garbling::garble","",4,[[["self"],["garbledcircuit"]],["bool"]]],[11,"ne","","",4,[[["self"],["garbledcircuit"]],["bool"]]],[11,"eq","","",5,[[["self"],["encoder"]],["bool"]]],[11,"ne","","",5,[[["self"],["encoder"]],["bool"]]],[11,"eq","","",6,[[["self"],["decoder"]],["bool"]]],[11,"ne","","",6,[[["self"],["decoder"]],["bool"]]],[11,"eq","fancy_garbling::wire","",7,[[["self"],["wire"]],["bool"]]],[11,"ne","","",7,[[["self"],["wire"]],["bool"]]],[11,"eq","fancy_garbling::circuit","",14,[[["self"],["circuitref"]],["bool"]]],[11,"ne","","",14,[[["self"],["circuitref"]],["bool"]]],[11,"eq","","",15,[[["self"],["circuit"]],["bool"]]],[11,"ne","","",15,[[["self"],["circuit"]],["bool"]]],[11,"eq","","",16,[[["self"],["gate"]],["bool"]]],[11,"ne","","",16,[[["self"],["gate"]],["bool"]]],[11,"clone","fancy_garbling::wire","",7,[[["self"]],["wire"]]],[11,"clone","fancy_garbling::fancy","",11,[[["self"]],["bundle"]]],[11,"clone","fancy_garbling::dummy","",19,[[["self"]],["dummyval"]]],[11,"clone","fancy_garbling::informer","",20,[[["self"]],["informerval"]]],[11,"clone","fancy_garbling::circuit","",14,[[["self"]],["circuitref"]]],[11,"clone","","",15,[[["self"]],["circuit"]]],[11,"clone","","",16,[[["self"]],["gate"]]],[11,"fmt","fancy_garbling::garble","",0,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",4,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",5,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",6,[[["self"],["formatter"]],["result"]]],[11,"fmt","fancy_garbling::wire","",7,[[["self"],["formatter"]],["result"]]],[11,"fmt","fancy_garbling::dummy","",19,[[["self"],["formatter"]],["result"]]],[11,"fmt","fancy_garbling::informer","",20,[[["self"],["formatter"]],["result"]]],[11,"fmt","fancy_garbling::circuit","",14,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",15,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",16,[[["self"],["formatter"]],["result"]]],[11,"serialize","fancy_garbling::garble","",4,[[["self"],["__s"]],["result"]]],[11,"serialize","","",5,[[["self"],["__s"]],["result"]]],[11,"serialize","","",6,[[["self"],["__s"]],["result"]]],[11,"serialize","","",0,[[["self"],["__s"]],["result"]]],[11,"serialize","fancy_garbling::wire","",7,[[["self"],["__s"]],["result"]]],[11,"serialize","fancy_garbling::circuit","",14,[[["self"],["__s"]],["result"]]],[11,"serialize","","",15,[[["self"],["__s"]],["result"]]],[11,"serialize","","",16,[[["self"],["__s"]],["result"]]],[11,"deserialize","fancy_garbling::garble","",4,[[["__d"]],["result"]]],[11,"deserialize","","",5,[[["__d"]],["result"]]],[11,"deserialize","","",6,[[["__d"]],["result"]]],[11,"deserialize","","",0,[[["__d"]],["result"]]],[11,"deserialize","fancy_garbling::wire","",7,[[["__d"]],["result"]]],[11,"deserialize","fancy_garbling::circuit","",14,[[["__d"]],["result"]]],[11,"deserialize","","",15,[[["__d"]],["result"]]],[11,"deserialize","","",16,[[["__d"]],["result"]]]],"paths":[[4,"Message"],[4,"GateType"],[3,"Garbler"],[3,"Evaluator"],[3,"GarbledCircuit"],[3,"Encoder"],[3,"Decoder"],[4,"Wire"],[8,"HasModulus"],[8,"Fancy"],[8,"BundleGadgets"],[3,"Bundle"],[3,"Dummy"],[3,"Informer"],[3,"CircuitRef"],[3,"Circuit"],[4,"Gate"],[3,"CircuitBuilder"],[8,"RngExt"],[3,"DummyVal"],[3,"InformerVal"]]};
initSearch(searchIndex);
