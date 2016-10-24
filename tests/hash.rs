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
    let x3 = "Governments of the Industrial World, you weary giants of flesh and steel, I come from Cyberspace, the new home of Mind. On behalf of the future, I ask you of the past to leave us alone. You are not welcome among us. You have no sovereignty where we gather. We have no elected government, nor are we likely to have one, so I address you with no greater authority than that with which liberty itself always speaks. I declare the global social space we are building to be naturally independent of the tyrannies you seek to impose on us. You have no moral right to rule us nor do you possess any methods of enforcement we have true reason to fear.".as_bytes();
    let test = "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28";
    let test2 = "a77abe1ccf8f5497e228fbc0acd73a521ededb21b89726684a6ebbc3baa32361aca5a244daa84f24bf19c68baf78e6907625a659b15479eb7bd426fc62aafa73";
    let test3 = "c76d9a8b804949813e2a78e06328390bc8a4e055102c4bca80a502f7f21f9517938b2b42cdbe5bea386bb25c57e840f922462c81b81d3b73269282495e23d0d9";

    let mut h = [0u8; 64];

    tweetnacl::crypto_hash(&mut h[..], &x[..]);
    assert_eq!(&h[..].to_hex(), test);

    tweetnacl::crypto_hash(&mut h[..], &x2[..]);
    assert_eq!(&h[..].to_hex(), test2);

    tweetnacl::crypto_hash(&mut h[..], &x3[..]);
    assert_eq!(&h[..].to_hex(), test3);
}