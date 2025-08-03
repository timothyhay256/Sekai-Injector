use std::{net::SocketAddr, path::Path, sync::Arc};

use axum::{
    BoxError,
    body::Body,
    extract::{Request, State},
    handler::HandlerWithoutStateExt,
    http::{StatusCode, uri::Authority},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Host;
use hyper::Uri;
use log::{debug, error, info};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

use crate::{
    RequestParams, RequestStatus,
    utils::{Manager, Ports},
};

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

    let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => panic!(
            "Failed to bind to 0.0.0.0:{}! You probably need to either run with root/admin, or run sudo setcap 'cap_net_bind_service=+ep' /path/to/binary to allow serving on port {}. Error: {}",
            ports.http, ports.http, e
        ),
    };

    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}

pub async fn handler(
    Host(host): Host,
    State(state): State<Arc<RwLock<Manager>>>,
    mut request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let mut request_params: RequestParams = (RequestStatus::Forwarded, path.clone(), None);

    debug!("Handling request for {path}");

    let should_inject = {
        let guard = state.read().await;
        guard.config.inject_resources && guard.injection_hashmap.contains_key(&path)
    };

    if should_inject {
        let local_file_path = {
            let guard = state.read().await;
            Path::new(&guard.injection_hashmap[&host][&path].0).to_path_buf()
        };

        match tokio::fs::File::open(&local_file_path).await {
            Ok(file_content) => {
                info!("Injecting {} to request {path}!", local_file_path.display());

                state.write().await.statistics.request_count.0 += 1;
                request_params.0 = RequestStatus::Proxied;
                request_params.2 = Some(local_file_path.display().to_string());

                // convert the `AsyncRead` into a `Stream`
                let stream = ReaderStream::new(file_content);
                // convert the `Stream` into an `axum::body::HttpBody`
                let body = axum::body::Body::from_stream(stream);

                return body.into_response();
            }
            Err(_) => {
                error!(
                    "Could not find {}, redirecting instead!",
                    local_file_path.display()
                );
            }
        }
    }

    info!("Proxying {path} to upstream host");
    let path_query = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(&path);

    let uri = format!("https://{host}{path_query}");

    *request.uri_mut() = Uri::try_from(uri).unwrap();

    let result = {
        let state_guard = state.read().await;
        state_guard.client.request(request).await
    };

    match result {
        Ok(request) => {
            {
                let mut state_guard = state.write().await;
                state_guard.statistics.request_count.1 += 1;
                state_guard.statistics.requests.push(request_params);
            }
            request.into_response()
        }
        Err(e) => {
            error!("Failed to make request to upstream host: {e}");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}
