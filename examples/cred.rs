use cross_krb5::{Cred, K5Ctx};
use libgssapi::credential::{Cred as GssCred, CredUsage};

fn main() {
    let mut gss_cred = GssCred::acquire(None, None, CredUsage::Accept, None).unwrap();
    let cred: Cred = Cred::from(gss_cred); // To krb5-cross compatible
    gss_cred = cred.into(); // and back
}
