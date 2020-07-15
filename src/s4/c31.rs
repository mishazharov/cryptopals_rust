#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;
    use serde::Deserialize;
    use warp::Filter;
    use std::{thread, time};
    use rand;
    use rand::Rng;
    use rand::distributions::Standard;
    use hyper::{Body, client::Client, Request};
    use std::convert::Infallible;
    use crate::hashing::{hmac::hmac, sha1::{sha1, SHA1_LEN_BYTES}, hash_padding::HASH_BLOCK_LEN_BYTES};
    // For flushing
    use std::io;
    use std::io::prelude::*;

    #[derive(Deserialize)]
    struct Params {
        file: String,
        signature: String,
    }

    fn cmd_bytes_slow(vec1: &[u8], vec2: &[u8]) -> bool {
        if vec1.len() != vec2.len() {
            println!("Your lengths are different...");
            return false;
        }

        for i in 0..vec1.len() {
            if vec1[i] != vec2[i] {
                return false;
            }
            thread::sleep(time::Duration::from_millis(5));
        }

        true
    }

    fn validate(payload: &Params, key: &[u8]) -> bool {
        let expected = hmac(key, payload.file.as_bytes(), sha1, HASH_BLOCK_LEN_BYTES);

        let decoded = hex::decode(payload.signature.as_bytes()).unwrap();
        cmd_bytes_slow(&expected, &decoded)
    }

    // Returns true if the attack succeeded... (?)
    // `file` might as well be ascii
    async fn attack_server(file: &[u8]) -> Result<Vec<u8>, ()> {
        let mut hash = vec![0u8; SHA1_LEN_BYTES];

        let new_file = String::from_utf8_lossy(file);

        let client = Client::new();
        for index in 0..hash.len() {
            let mut guess_results = vec![time::Duration::new(0, 0); 256];

            for guess in 0u8..=255 {
                hash[index] = guess;

                let uri = format!(
                    "http://localhost:1337/test?file={}&signature={}",
                    new_file,
                    &hex::encode(&hash)
                );

                let request = Request::get(
                    uri
                ).body(Body::from("")).unwrap();

                let start = time::Instant::now();
                let response = client.request(request).await.unwrap();
                guess_results[guess as usize] = start.elapsed();

                let status = response.status();
                if status == hyper::StatusCode::OK {
                    println!("\nFound hash on index {}", index);
                    return Ok(hash)
                }
            }

            let res = guess_results.iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.cmp(b))
                .map(|(index, _)| index).unwrap() as u8;
            
            // Used to indicate progress for the impatient types
            print!("{:02x}", res);
            io::stdout().flush().unwrap();

            hash[index] = res;
        }
        println!();

        let request = Request::get(
            format!(
                "http://localhost:1337/test?file={}&signature={}",
                new_file,
                &hex::encode(&hash)
            )
        ).body(Body::from("")).unwrap();
        let response = client.request(request);

        if response.await.unwrap().status() == hyper::StatusCode::OK {
            Ok(hash)
        } else {
            println!("Failed to get hash! Result: {}", &hex::encode(&hash));
            Err(())
        }
    }

    async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
        println!("{:?}", err);
        Ok(warp::reply::with_status("", warp::http::StatusCode::BAD_REQUEST))
    }

    #[tokio::test]
    async fn break_hmac_non_constant_time() {
        let key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(
            HASH_BLOCK_LEN_BYTES
        ).collect();
        let key_1 = key.to_vec();

        let broken_endpoint = warp::path!("test")
            .and(warp::query::<Params>())
            .map(
                move |name: Params| {
                    if validate(&name, &key) {
                        warp::reply::with_status(":)", warp::http::StatusCode::OK)
                    } else {
                        warp::reply::with_status(":(", warp::http::StatusCode::FORBIDDEN)
                    }
                }
            );
        
        let routes = warp::get().and(broken_endpoint).recover(handle_rejection);
        
        let (tx, rx) = oneshot::channel::<()>();

        let (_, server) = warp::serve(routes)
            .bind_with_graceful_shutdown((
                [127, 0, 0, 1], 1337),
                async {
                    rx.await.ok();
                }
            );
        
        tokio::task::spawn(server);

        let message = "The_spy_has_already_breached_our_defenses".as_bytes();
        let expected = hmac(&key_1, message, sha1, HASH_BLOCK_LEN_BYTES);
        println!("Starting attack run. Would like: {}", &hex::encode(&expected));
        let res = attack_server(&message);

        match res.await {
            Ok(val) => {
                assert_eq!(expected, val);
            },
            Err(_) => {
                println!("Failed to get hash! Wanted: {}", &hex::encode(&expected));
                assert!(false);
            }
        }

        let _ = tx.send(());
    }
}
