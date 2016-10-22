//
// Test vectors adapted from libsodium
//

extern crate tweetnacl;
extern crate rustc_serialize;

use rustc_serialize::hex::ToHex;

#[test]
fn hash() {
    let x = "testing\n".as_bytes();
    let x2 = "The Conscience of a Hacker is a small essay written January 8, 1986 by a computer security hacker who went by the handle of The Mentor, who belonged to the 2nd generation of Legion of Doom.".as_bytes();
    let test = "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28";
    let test2 = "a77abe1ccf8f5497e228fbc0acd73a521ededb21b89726684a6ebbc3baa32361aca5a244daa84f24bf19c68baf78e6907625a659b15479eb7bd426fc62aafa73";
    let mut h = [0u8; 64];

    tweetnacl::crypto_hash(&mut h[..], &x[..]);
    assert_eq!(&h[..].to_hex(), test);

    tweetnacl::crypto_hash(&mut h[..], &x2[..]);
    assert_eq!(&h[..].to_hex(), test2);
}