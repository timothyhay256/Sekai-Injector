use crate::utils::{Config, Ports};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::{
    BoxError,
    body::Body,
    extract::Request,
    handler::HandlerWithoutStateExt,
    http::{StatusCode, uri::Authority},
    response::Redirect,
};

use axum_extra::extract::Host;
use hyper::Uri;
use std::net::SocketAddr;

#[allow(dead_code)]
pub async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: &str, uri: Uri, https_port: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let authority: Authority = host.parse()?;
        let bare_host = match authority.port() {
            Some(port_struct) => authority
                .as_str()
                .strip_suffix(port_struct.as_str())
                .unwrap()
                .strip_suffix(':')
                .unwrap(), // if authority.port() is Some(port) then we can be sure authority ends with :{port}
            None => authority.as_str(),
        };

        parts.authority = Some(format!("{bare_host}:{https_port}").parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(&host, uri, ports.https) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}

pub async fn handler(State(state): State<Config>, request: Request<Body>) -> impl IntoResponse {
    let path = request.uri().path().to_string();

    // // Check if the path should return a local file
    // if let Some(local_file_path) = state.local_files.get(&path) {
    //     // Serve the local file
    //     if let Ok(file_content) = fs::read(local_file_path).await {
    //         Ok(Response::new(Body::from(file_content)))
    //     } else {
    //         Ok(Response::builder()
    //             .status(StatusCode::NOT_FOUND)
    //             .body(Body::from("File not found"))
    //             .unwrap())
    //     }
    // } else {
    //     // Forward the request to the upstream server
    //     forward_request(request, &state.upstream_url).await
    // }
    // forward_request(request, &state.upstream_host).await
    Redirect::permanent(&format!("{}/{}", state.upstream_host, path))
}
