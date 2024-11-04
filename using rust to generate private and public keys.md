In this section, we will going to design wallet for our blockchain application. In order to do that, we need some basic knowledge about cpryptography base on ellitic curve, some information are given at the following link:

https://github.com/wycl16514/golang-bitcoin-elliptic-curve/blob/main/Coding%20points%20on%20elliptic%20curve.md

Following I will assume you already know the concept of public key and private key base on elliptic curve, now let's see how we can generate the key pair by using rust, first we need to install the dependency, in cargo.tmol add following:
```rs
[dependencies]
p256 = { version = "0.13", features = ["ecdsa","arithmetic"] }
rand_core = "0.6"
```
Then in the main.rs, we add the following code:
```rs
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

fn main() {
    // Step 1: Generate a private key
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Print the key pair
    println!("Private Key: {:?}", signing_key.to_bytes());
    println!("Public Key: {:?}", verifying_key.to_encoded_point(false));

    // Step 2: Define a message to sign
    let message = b"Hello, ECDSA!";

    // Step 3: Sign the message
    let signature: Signature = signing_key.sign(message);
    println!("Signature: {:?}", signature);

    // Step 4: Verify the signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified successfully!"),
        Err(_) => println!("Failed to verify the signature."),
    }
}

```
We don't need to go to the math details about how to add points on ellitic curve to generate public key and private key, all the chores are handled by given crats. The code aboved generate private key and public key, the private key is 
actually a huge random number, the public key is using the random number to mulitply the generator point on the elliptic curve. Then we can use the private key to "sign" on given message, this actually is using the private key to encrypt
the given message, and the encried message can only be decried by the public key, if we can restore the encried message back to its original content, then we can make sure the message is really issued by the true owner of the public key.
