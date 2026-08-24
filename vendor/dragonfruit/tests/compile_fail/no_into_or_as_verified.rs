                                                                                      
                                                                                   
                                                                                      
                                    
#![allow(unused)]
fn wua() -> dragonfruit::WindowUncheckedArtifact {
    unimplemented!()
}
fn va() -> dragonfruit::VerifiedArtifact {
    unimplemented!()
}
fn main() {
    let _: dragonfruit::VerifiedArtifact = wua().into();
    let _: dragonfruit::WindowUncheckedArtifact = va().into();
    let _ = wua().as_verified();
}
