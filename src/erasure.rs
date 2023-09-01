use reed_solomon_novelpoly::WrappedShard;

pub struct Erasure<const VALIDATORS: usize>();

impl<const VALIDATORS: usize> Erasure<VALIDATORS> {
    pub fn encodify(data: &[u8]) -> anyhow::Result<Vec<WrappedShard>> {
        Ok(reed_solomon_novelpoly::encode(data, VALIDATORS)?)
    }

    pub fn recover(data: Vec<Option<WrappedShard>>) -> anyhow::Result<Vec<u8>> {
        Ok(reed_solomon_novelpoly::reconstruct(data, VALIDATORS)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_recover() {
        let e = Erasure::<4>::encodify(b"hello").unwrap();

        let recover = Erasure::<4>::recover(e.clone().into_iter().map(Some).collect()).unwrap();

        assert!(recover.starts_with(b"hello"));
    }

    #[test]
    fn test_encode_recover_one_third() {
        let data = b"he1lohe2lohe3lohe4lohe5lohe6lohe7lohe8lo";
        println!("original {:?}", data);
        const N: usize = 8;

        let mut codewords: Vec<Option<WrappedShard>> = Erasure::<N>::encodify(data)
            .unwrap()
            .into_iter()
            .map(Some)
            .collect();
        println!("codewords {:#?}({})", codewords, codewords.len());

        codewords[0] = None;
        codewords[1] = None;
        codewords[2] = None;
        codewords[N - 3] = None;
        codewords[N - 2] = None;
        codewords[N - 1] = None;
        println!("codewords {:#?}({})", codewords, codewords.len());

        let recover = Erasure::<N>::recover(codewords).unwrap();
        println!("recover {:?}", recover);
        assert!(recover.starts_with(data));
    }
}
