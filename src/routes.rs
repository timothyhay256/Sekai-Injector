use std::{net::SocketAddr, sync::Arc};

use axum::{
    BoxError,
    body::Body,
    extract::{Request, State},
    handler::HandlerWithoutStateExt,
    http::{StatusCode, uri::Authority},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Host;
use hyper::Uri;
use log::{debug, error, info};
use tokio::{fs, sync::RwLock};

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
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}

pub async fn handler(
    State(state): State<Arc<RwLock<Manager>>>,
    mut request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let mut request_params: RequestParams = (RequestStatus::Forwarded, path.clone(), None);

    debug!("Handling request for {path}");

    if state.read().await.config.inject_resources {
        if let Some(local_file_path) = state.read().await.injection_hashmap.get(&path) {
            let local_file_path = local_file_path.0.clone();

            match fs::read(&local_file_path).await {
                Ok(file_content) => {
                    info!("Injecting {local_file_path} to request {path}!");
                    state.write().await.statistics.request_count.0 += 1;
                    request_params.0 = RequestStatus::Proxied;
                    request_params.2 = Some(local_file_path);
                    return Response::new(Body::from(file_content));
                }
                Err(_) => {
                    error!("Could not find {local_file_path}, redirecting instead!");
                }
            }
        }
    }

    info!("Proxying {path} to upstream host");
    let path_query = request
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(&path);

    let uri = format!(
        "https://{}{}",
        state.read().await.config.upstream_host,
        path_query
    );

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
