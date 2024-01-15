use borsh::BorshSerialize;
use plonky2x::{
    frontend::{hint::simple::hint::Hint, uint::Uint},
    prelude::{
        ByteVariable, CircuitBuilder, CircuitVariable, PlonkParameters, U32Variable, U64Variable,
        ValueStream,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BorshCodec;

impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for BorshCodec {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        todo!()
    }
}

// THis isnt quite right, we should probably implement borsh for generic types here but its
// annoying
pub trait Borsh: Sized {
    fn encodeb<L: PlonkParameters<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<L, D>,
    ) -> Vec<ByteVariable>;
    fn decodeb<L: PlonkParameters<D>, const D: usize>(
        builder: &mut CircuitBuilder<L, D>,
        bytes: &[ByteVariable],
    ) -> Self;
}

// impl Borsh for U64Variable {
//     fn encodeb<L: PlonkParameters<D>, const D: usize>(
//         &self,
//         builder: &mut CircuitBuilder<L, D>,
//     ) -> Vec<ByteVariable> {
//         let x = self.variables()[0];
//         builder.beacon_get_block_header(block_root)
// <U64Variable as Uint<2>>::to_little_endian(&self, &mut vec![]);
// U64Target::from(self).encode(builder);
// self.limbs
//     .iter()
//     .rev()
//     .flat_map(|x| x.encode(builder))
//     .collect::<Vec<_>>()
//}

// fn decodeb<L: PlonkParameters<D>, const D: usize>(
//     builder: &mut CircuitBuilder<L, D>,
//     bytes: &[ByteVariable],
// ) -> Self {
//     assert_eq!(bytes.len(), 2 * 4);
//     let mut limbs = [U32Variable::init_unsafe(builder); 2];
//     limbs[0].to_little_endian(&mut bytes[0..4]);
//     U32Variable::from_variables(builder, variables)
//     for i in 0..2 {
//         limbs[i] = U32Variable::decodeb(builder, &bytes[i * 4..(i + 1) * 4]);
//     }
//     limbs.reverse();
//     Self { limbs }
// }
//}

// fn serialize<W: Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
//     let mut bytes = vec![];
//     self.0.to_little_endian(&mut bytes);
//     writer.write_all(&bytes)
// }
//
// fn deserialize<R: std::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
//     let mut bytes = vec![];
//     reader.read_to_end(&mut bytes)?;
//     Ok(Borshable(<T>::from_little_endian(&bytes)))
// }
//
macro_rules! borsh_integer {
    ($a:ident, $b:ty, $c:expr) => {
        impl Borsh for $a {
            fn encodeb<L: PlonkParameters<D>, const D: usize>(
                &self,
                builder: &mut CircuitBuilder<L, D>,
            ) -> Vec<ByteVariable> {
                self.limbs
                    .iter()
                    .rev()
                    .flat_map(|x| x.encode(builder))
                    .collect::<Vec<_>>()
            }

            fn decodeb<L: PlonkParameters<D>, const D: usize>(
                builder: &mut CircuitBuilder<L, D>,
                bytes: &[ByteVariable],
            ) -> Self {
                assert_eq!(bytes.len(), $c * 4);
                let mut limbs = [U32Variable::init_unsafe(builder); $c];
                for i in 0..$c {
                    limbs[i] = U32Variable::decodeb(builder, &bytes[i * 4..(i + 1) * 4]);
                }
                limbs.reverse();
                Self { limbs }
            }
        }
    };
}
