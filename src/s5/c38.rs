#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use crate::asymmetric::srp::SrpServer;
    use crate::asymmetric::srp::SrpClient;
    use crate::asymmetric::diffie_hellman::DiffieHellmanContext;
    use num_traits::Zero;
    use num_traits::One;
    use num_bigint::BigInt;
    use num_bigint::RandBigInt;
    use openssl::{sha::sha256, sign::Signer, hash::MessageDigest, pkey::PKey};

    #[test]
    fn test_last_srp_normal() {
        let pw = "I am the medic".as_bytes();

        let mut server = SrpServer::new(pw);
        let mut client = SrpClient::new();

        let (salt, pkey, u) = server.variant_initial_req(&client.dh.public_key).unwrap();
        client.set_salt_and_pkey_variant(&salt, &pkey, pw, &u);

        assert!(server.is_ok(&client.get_hmac()));
    }

    // Not going to actually write a server object for this
    #[test]
    fn test_offline_dictionary() {
        let dictionary = ["scout", "pyro", "heavy", "demo", "soldier", "medic", "spy", "sniper", "engie"];
        let pw = dictionary.choose(&mut rand::thread_rng()).unwrap();

        let mut server_dh = DiffieHellmanContext::nist();

        let private_key = rand::thread_rng().gen_bigint_range(
            &BigInt::from(2),
            &server_dh.p
        );
        server_dh.set_private_key(&private_key);

        let salt: BigInt = Zero::zero();

        let mut client = SrpClient::new();
        client.set_salt_and_pkey_variant(
            &salt,
            &server_dh.public_key,
            pw.as_bytes(), // allowed to use the PW here to initialize the client
            &One::one()
        );

        // No use of PW below this line
        let desired_hash = client.get_hmac();

        // Dictionary attack
        for ele in dictionary.iter() {
            let mut to_hash: Vec<u8> = salt.to_bytes_be().1;
            to_hash.extend_from_slice(ele.as_bytes());
            let x_h = sha256(&to_hash);
            let x = BigInt::from_bytes_be(num_bigint::Sign::Plus, &x_h);
            let k = server_dh.make_session_key(&(&client.dh.public_key * server_dh.g.modpow(&x, &server_dh.p)));

            let pkey = PKey::hmac(&k.to_bytes_be().1).unwrap();
            let mut signer = Signer::new(
                MessageDigest::sha256(),
                &pkey
            ).unwrap();
            signer.update(&salt .to_bytes_be().1).unwrap();
            let hmac = signer.sign_to_vec().unwrap();

            if hmac == desired_hash {
                // Success
                return
            }
        }

        assert!(false);
    }
}
