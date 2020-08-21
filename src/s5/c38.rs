#[cfg(test)]
mod tests {
    use crate::asymmetric::srp::SrpServer;
    use crate::asymmetric::srp::SrpClient;

    #[test]
    fn test_last_srp_normal() {
        let pw = "I am the medic".as_bytes();

        let mut server = SrpServer::new(pw);
        let mut client = SrpClient::new();

        let (salt, pkey, u) = server.variant_initial_req(&client.dh.public_key).unwrap();
        client.set_salt_and_pkey_variant(&salt, &pkey, pw, &u);

        assert!(server.is_ok(&client.get_hmac()));
    }
}
