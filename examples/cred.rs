use cross_krb5::Cred;
use libgssapi::credential::{Cred as GssCred, CredUsage};

fn main() {
    let mut _gss_cred = GssCred::acquire(None, None, CredUsage::Accept, None).unwrap();
    let cred: Cred = Cred::from(_gss_cred); // To krb5-cross compatible
    _gss_cred = cred.into(); // and back
}
