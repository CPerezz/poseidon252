use bulletproofs::r1cs::{LinearCombination, Variable};
use curve25519_dalek::scalar::Scalar;
use std::ops::Mul;

fn parse_to_scalar(bytes: &[u8]) -> Vec<Scalar> {
  bytes
    .chunks(32)
    .map(|x| {
      let mut raw: [u8; 32] = [0; 32];
      raw.copy_from_slice(&x);
      Scalar::from_bytes_mod_order(raw)
    })
    .collect()
}

lazy_static! {
  pub static ref ARK: Vec<Scalar> = {
    let scalars: Vec<Scalar> = parse_to_scalar(include_bytes!("ark.bin"));
    assert_eq!(scalars.len(), 960);
    scalars
  };
}

lazy_static! {
  pub static ref MDS: Vec<Scalar> = {
    let scalars: Vec<Scalar> = parse_to_scalar(include_bytes!("mds.bin"));
    assert_eq!(scalars.len(), 36);
    scalars
  };
}

impl<'a> Mul<&'a MDS> for Vec<Scalar> {
  type Output = Vec<Scalar>;
  fn mul(self, rhs: &'a MDS) -> Vec<Scalar> {
    let mut scalars: Vec<Scalar> = Vec::with_capacity(6);
    for i in (0..36).step_by(6) {
      scalars.push(
        rhs[i] * self[0]
          + rhs[i + 1] * self[1]
          + rhs[i + 2] * self[2]
          + rhs[i + 3] * self[3]
          + rhs[i + 4] * self[4]
          + rhs[i + 5] * self[5],
      )
    }
    scalars
  }
}

impl<'a> Mul<&'a MDS> for Vec<Variable> {
  type Output = Vec<LinearCombination>;
  fn mul(self, rhs: &'a MDS) -> Vec<LinearCombination> {
    let mut lc: Vec<LinearCombination> = Vec::with_capacity(6);
    for i in (0..36).step_by(6) {
      lc.push(
        rhs[i] * self[0]
          + rhs[i + 1] * self[1]
          + rhs[i + 2] * self[2]
          + rhs[i + 3] * self[3]
          + rhs[i + 4] * self[4]
          + rhs[i + 5] * self[5],
      )
    }
    lc
  }
}
