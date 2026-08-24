                                                                                      
                                                                             
                                                                                       
                                                                                       
                                                                               
#![allow(unused)]
fn wua() -> dragonfruit::WindowUncheckedArtifact {
    unimplemented!()
}
fn va() -> dragonfruit::VerifiedArtifact {
    unimplemented!()
}
fn accept_both<T: AsRef<[u8; 32]>>(_proof: T) {}
fn main() {
    accept_both(wua());
    accept_both(va());
}
