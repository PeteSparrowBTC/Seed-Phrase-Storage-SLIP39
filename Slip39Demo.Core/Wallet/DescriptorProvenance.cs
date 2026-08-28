namespace Slip39Demo.Core.Wallet;

// Where the wallet descriptor in a backup came from. Recorded in
// verification-record.txt because the two are not equally trustworthy: a computed
// descriptor was derived from the seeds in this form and comes with an address that was
// derived the same way, while a pasted one was typed by a human and checked by nothing
// here. An owner reading the record years later cannot tell the two apart otherwise.
public enum DescriptorProvenance
{
    // No descriptor in this backup.
    NotRecorded,

    // Derived from the cosigner seeds by MultisigWallet.
    Computed,

    // Supplied by the owner, stored as given.
    Pasted,
}
