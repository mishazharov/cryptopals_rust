#[cfg(test)]
mod tests {
    use std::{sync::{Arc, RwLock}, collections::HashMap};
    use warp::Filter;
    use crate::asymmetric::srp::{SrpClient, SrpServer};
    use num_bigint::BigInt;
    use num_bigint::Sign::Plus;
    use tokio::sync::oneshot;
    use hyper::{client::Client, Request, Body};
    use serde::{Serialize, Deserialize};
    use openssl::sha::sha256;

    pub type Db = Arc<RwLock<HashMap<String, SrpServer>>>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SaltResponse {
        salt: String,
        pkey: String,
    }

    fn with_db(db: Db) -> impl Filter<Extract = (Db,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
    }

    fn send_public_key(user_db: Db) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("send_public_key")
            .and(warp::body::form())
            .and(with_db(user_db))
            .and(warp::post()).and_then(
                |params: HashMap<String, String>, db: Db| async move {
                    match params.get(&String::from("username")) {
                        Some(username) => {
                            println!("Found username {}", username);
                            let mut server = SrpServer::new("hunter2".as_bytes());
                            let pkey = hex::decode(params.get("pkey").unwrap()).unwrap();

                            let (salt, server_pkey) = server.initial_req(
                                &BigInt::from_bytes_be(Plus, &pkey)
                            ).unwrap();

                            let mut db = db.write().unwrap();
                            db.insert(From::from(username), server);

                            let mut res: HashMap<String, String> = HashMap::new();
                            res.insert(String::from("salt"), hex::encode(&salt.to_bytes_be().1));
                            res.insert(String::from("pkey"), hex::encode(&server_pkey.to_bytes_be().1));
                            return Ok(warp::reply::json(&res));
                        },
                        None => {
                            // Need a username to connect
                            return Err(warp::reject::reject())
                        }
                    }
                }
        )
    }

    fn verify(user_db: Db) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("verify")
            .and(warp::body::form())
            .and(with_db(user_db))
            .and(warp::post()).and_then(
                |params: HashMap<String, String>, db: Db| async move {
                    let hmac = hex::decode(params.get("hmac").unwrap()).unwrap();
                    let db = db.write().unwrap();
                    let server = db.get(From::from(params.get("username").unwrap())).unwrap();

                    match server.is_ok(&hmac) {
                        true => return Ok(warp::reply::reply()),
                        false => {
                            println!("Not authed");
                            return Err(warp::reject::not_found())
                        }
                    }
                }
            )
    }

    fn srp_endpoint(user_db: Db) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path("login")
            .and(
                send_public_key(user_db.clone()).or(verify(user_db.clone()))
            )
    }

    fn start_server(port: u16, user_db: Db) -> tokio::sync::oneshot::Sender<()> {
        let (tx, rx) = oneshot::channel::<()>();

        let route = srp_endpoint(user_db);

        let (_, server) = warp::serve(route)
            .bind_with_graceful_shutdown((
                [127, 0, 0, 1], port),
                async {
                    rx.await.ok();
                }
            );

        tokio::task::spawn(server);

        tx
    }

    #[tokio::test]
    async fn test_srp_regular() {
        let db: Db = Arc::new(
            RwLock::new(HashMap::new())
        );

        let mut c = SrpClient::new();

        let tx = start_server(1338, db);
        let pkey = hex::encode(c.dh.public_key.to_bytes_be().1);

        let req = Request::post("http://127.0.0.1:1338/login/send_public_key")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("username=lol&pkey={}", pkey))).unwrap();

        let client = Client::new();
        let response = client.request(req).await.unwrap();
        assert_eq!(&response.status(), &hyper::http::StatusCode::OK);

        let body = response.into_body();

        let salt_and_server_pkey: SaltResponse = serde_json::from_slice(
            &hyper::body::to_bytes(body).await.unwrap()
        ).unwrap();

        c.set_salt_and_pkey(
            &BigInt::from_bytes_be(Plus, &hex::decode(salt_and_server_pkey.salt).unwrap()),
            &BigInt::from_bytes_be(Plus, &hex::decode(salt_and_server_pkey.pkey).unwrap()),
            "hunter2".as_bytes()
        );

        let req = Request::post("http://127.0.0.1:1338/login/verify")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("username=lol&hmac={}", hex::encode(c.get_hmac())))).unwrap();

        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), hyper::http::StatusCode::OK);

        // Shut down the server
        tx.send(()).unwrap();
    }

    #[tokio::test]
    async fn test_srp_zero() {
        let db: Db = Arc::new(
            RwLock::new(HashMap::new())
        );

        let mut c = SrpClient::new();

        let tx = start_server(1339, db);

        let req = Request::post("http://127.0.0.1:1339/login/send_public_key")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("username=lol&pkey=00")).unwrap();

        let client = Client::new();
        let response = client.request(req).await.unwrap();
        assert_eq!(&response.status(), &hyper::http::StatusCode::OK);

        let body = response.into_body();

        let salt_and_server_pkey: SaltResponse = serde_json::from_slice(
            &hyper::body::to_bytes(body).await.unwrap()
        ).unwrap();

        c.attacker_set_shared_key(
            Some(sha256(&[0u8]).to_vec()),
            &BigInt::from_bytes_be(
                Plus,
                &hex::decode(salt_and_server_pkey.salt).unwrap()
            )
        );

        let req = Request::post("http://127.0.0.1:1339/login/verify")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("username=lol&hmac={}", hex::encode(c.get_hmac())))).unwrap();

        let response = client.request(req).await.unwrap();
        assert_eq!(response.status(), hyper::http::StatusCode::OK);

        // Shut down the server
        tx.send(()).unwrap();
    }

    #[tokio::test]
    async fn test_srp_n() {
        let db: Db = Arc::new(
            RwLock::new(HashMap::new())
        );

        let mut c = SrpClient::new();

        let tx = start_server(1340, db);

        for i in 0..5 {
            let req = Request::post("http://127.0.0.1:1340/login/send_public_key")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                Body::from(
                    format!("username=lol&pkey={}",
                    hex::encode(
                            &c.dh.p.checked_mul(
                                &BigInt::from(i)
                            ).unwrap().to_bytes_be().1
                        )
                    )
                )
            ).unwrap();

            let client = Client::new();
            let response = client.request(req).await.unwrap();
            assert_eq!(&response.status(), &hyper::http::StatusCode::OK);

            let body = response.into_body();

            let salt_and_server_pkey: SaltResponse = serde_json::from_slice(
                &hyper::body::to_bytes(body).await.unwrap()
            ).unwrap();

            c.attacker_set_shared_key(
                Some(sha256(&[0u8]).to_vec()),
                &BigInt::from_bytes_be(
                    Plus,
                    &hex::decode(salt_and_server_pkey.salt).unwrap()
                )
            );

            let req = Request::post("http://127.0.0.1:1340/login/verify")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("username=lol&hmac={}", hex::encode(c.get_hmac())))).unwrap();

            let response = client.request(req).await.unwrap();
            assert_eq!(response.status(), hyper::http::StatusCode::OK);
        }

        // Shut down the server
        tx.send(()).unwrap();
    }
}
