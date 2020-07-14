use serde::Deserialize;
use warp::Filter;

#[derive(Deserialize)]
struct Params {
    file: Vec<u8>,
    _signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn break_hmac_non_constant_time() {
        let hello = warp::path!("test")
            .and(warp::query::<Params>())
            .map(
                |name: Params| format!("Hello, {:?}!", name.file)
            );
        
        let (tx, rx) = oneshot::channel::<()>();

        let (_, server) = warp::serve(hello)
            .bind_with_graceful_shutdown((
                [127, 0, 0, 1], 3030),
                async {
                    rx.await.ok();
                }
            );
        
        tokio::task::spawn(server);

        let _ = tx.send(());
    }
}
