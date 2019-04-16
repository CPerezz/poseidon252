use bulletproofs::r1cs::{ConstraintSystem, LinearCombination};
use curve25519_dalek::scalar::Scalar;
mod constants;
use constants::*;

#[macro_use]
extern crate lazy_static;

pub fn initialize() {
  lazy_static::initialize(&ARK);
  lazy_static::initialize(&MDS);
}

#[allow(non_snake_case)]
pub fn perm(S: Vec<Scalar>) -> Vec<Scalar> {
  let mut j = 0;
  let mut S = S;

  // Full Rounds
  for _ in 0..4 {
    for i in 0..6 {
      S[i] += ARK[j];
      S[i] = S[i].invert();
      j += 1;
    }
    S = S * &MDS;
  }

  // Partial Rounds
  for _ in 4..144 {
    for i in 0..6 {
      S[i] += ARK[j];
      j += 1;
    }
    S[5] = S[5].invert();
    S = S * &MDS;
  }

  // Full Rounds
  for _ in 144..148 {
    for i in 0..6 {
      S[i] += ARK[j];
      S[i] = S[i].invert();
      j += 1;
    }
    S = S * &MDS;
  }

  return S;
}

pub fn hash(left: Scalar, right: Scalar) -> Scalar {
  perm(vec![
    Scalar::zero(),
    left,
    right,
    Scalar::zero(),
    Scalar::zero(),
    Scalar::zero(),
  ])[1]
}

pub fn gadget<CS: ConstraintSystem>(
  _cs: &mut CS,
  _left: &LinearCombination,
  _right: &LinearCombination,
) -> (LinearCombination) {
  unimplemented!();
}

#[cfg(test)]
mod tests {
  use super::*;
  use curve25519_dalek::scalar::Scalar;

  fn scalar(s: &str) -> Scalar {
    let mut raw: [u8; 32] = [0; 32];

    raw.copy_from_slice(
      &s.as_bytes()
        .chunks(2)
        .map(std::str::from_utf8)
        .map(|x| u8::from_str_radix(&x.unwrap(), 16).unwrap())
        .collect::<Vec<u8>>(),
    );

    Scalar::from_bytes_mod_order(raw)
  }

  #[test]
  fn test_hash() {
    let a = scalar("d8f45699dd08e0fd6be08ee959bb305874aec008f90900a5ac2430576aa0f504");
    let b = scalar("5d3c3522616d44adf953eeae1f7825f18a0a933f9e54b0bdb75b33a751f5730a");

    assert_eq!(
      scalar("d1de2e9708ff905eed00423d43aa16b4183cb5daf292aead9d75244450fd2307"),
      hash(a, b)
    );

    assert_eq!(
      scalar("d38071558891495b5bfadaaba87cd703738dbda3541f34dd01fef807d133fc01"),
      hash(a, Scalar::zero())
    );
  }
}
