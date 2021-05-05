use fancy_garbling::{
    BinaryBundle,
    Bundle,
    BundleGadgets,
    CrtBundle,
    CrtGadgets,
    Fancy,
};

use itertools::Itertools;


pub fn check_equality<F: Fancy>(
    f: &mut F,
    x: &[F::Item],
    y: &[F::Item],
    byte_size: usize,
) -> Result<Vec<F::Item>, F::Error> {
    x.chunks(byte_size * 8)
    .zip_eq(y.chunks(byte_size * 8))
    .map(|(xs, ys)| {
        f.eq_bundles(
            &BinaryBundle::new(xs.to_vec()),
            &BinaryBundle::new(ys.to_vec()),
        )
    })
    .collect::<Result<Vec<F::Item>, F::Error>>()
}

pub fn unmask<F: Fancy>(
    f: &mut F,
    payload: &[F::Item],
    mask: &[F::Item],
    size: usize,
) -> Result<Vec<CrtBundle<F::Item>>, F::Error>{
    payload
        .chunks(size)
        .zip_eq(mask.chunks(size))
        .map(|(xp, tp)| {
            let b_x = Bundle::new(xp.to_vec());
            let b_t = Bundle::new(tp.to_vec());
            f.crt_sub(&CrtBundle::from(b_t), &CrtBundle::from(b_x))
        })
        .collect::<Result<Vec<CrtBundle<F::Item>>, F::Error>>()
}


pub fn weigh<F: Fancy>(
    f: &mut F,
    x: &[CrtBundle<F::Item>],
    y: &[F::Item],
    size: usize,
) -> Result<Vec<CrtBundle<F::Item>>, F::Error>{
    x.clone()
    .into_iter()
    .zip_eq(y.chunks(size))
    .map(|(ps, pr)|
        f.crt_mul(
            &ps,
            &CrtBundle::new(pr.to_vec()),
        )
    )
    .collect::<Result<Vec<CrtBundle<F::Item>>, F::Error>>()
}

pub fn expand_bit<F: Fancy>(
        f: &mut F,
        b: &F::Item,
        size: usize,
)-> Result<CrtBundle<F::Item>, F::Error> {
    let qs = &fancy_garbling::util::PRIMES[..size];
    let q = fancy_garbling::util::product(&qs);

    let one = f.crt_constant_bundle(1, q)?;
    let b_ws = one
        .iter()
        .map(|w| f.mul(w, &b))
        .collect::<Result<Vec<_>, _>>()?;
    let b_crt = CrtBundle::new(b_ws);
    Ok(b_crt)
}

pub fn sum_crt<F: Fancy>(
    f: &mut F,
    values: &[CrtBundle<F::Item>],
 )-> Result<CrtBundle<F::Item>, F::Error> {
    let q = values[0].composite_modulus();
    let mut acc = f.crt_constant_bundle(0, q)?;
    for v in values{
        acc = f.crt_add(&acc, &v).unwrap();
    }
    Ok(acc)
}
