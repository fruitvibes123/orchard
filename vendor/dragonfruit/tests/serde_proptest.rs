//! 1A AC#9: the fixed-width (de)serializer round-trips valid structs and NEVER
//! panics on arbitrary input (it either parses to an identical struct or errors).
use dragonfruit::{Attestation, Delegation, Purpose};
use proptest::prelude::*;

fn purpose_strategy() -> impl Strategy<Value = Purpose> {
    prop_oneof![
        Just(Purpose::Img),
        Just(Purpose::KexecVmlinuz),
        Just(Purpose::KexecInitramfs),
        Just(Purpose::Backup),
    ]
}

proptest! {
    #[test]
    fn delegation_roundtrips(
        wp in any::<[u8; 32]>(),
        purpose in purpose_strategy(),
        not_before in any::<u64>(),
        not_after in any::<u64>(),
        monotonic_ctr in any::<u64>(),
    ) {
        let d = Delegation { worker_pubkey: wp, purpose, not_before, not_after, monotonic_ctr };
        prop_assert_eq!(Delegation::from_canonical(&d.to_canonical()), Ok(d));
    }

    #[test]
    fn attestation_roundtrips(
        artifact_hash in any::<[u8; 32]>(),
        purpose in purpose_strategy(),
        delegation_id in any::<[u8; 32]>(),
    ) {
        let a = Attestation { artifact_hash, purpose, delegation_id };
        prop_assert_eq!(Attestation::from_canonical(&a.to_canonical()), Ok(a));
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                                                                                       
        let _ = Delegation::from_canonical(&bytes);
        let _ = Attestation::from_canonical(&bytes);
    }

    #[test]
    fn exact_length_bytes_parse_without_panic(
        mut d in proptest::collection::vec(any::<u8>(), 59..=59),
        mut a in proptest::collection::vec(any::<u8>(), 67..=67),
        purpose_byte in prop_oneof![0u8..=5, 6u8..=255],
    ) {
                                                                                
                                                                                    
                                                                                  
                                                                                     
                                                                                
                                                                                     
                                                                                   
                                                                         
                                                                                      
                                                                                  
                                                                            
        d[0] = 0x01;                  
        d[1] = 0x01;              
        d[34] = purpose_byte;                                   
        a[0] = 0x02;                   
        a[1] = 0x01;              
        a[34] = purpose_byte;                                    
        let _ = Delegation::from_canonical(&d);
        let _ = Attestation::from_canonical(&a);
    }
}
