//! The router and the server.

use std::sync::Arc;

use aegis_contracts::{Error, Result};
use aegis_core::Shutdown;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};

use crate::auth::Authenticator;
use crate::chatops::{self, ChatOps, Notifier};
use crate::config::ApiConfig;
use crate::console::console_router;
use crate::error::ApiError;
use crate::routes::{API_BASE, AppContext, Ctx, api_router, healthz};
use crate::security::{security_headers, time_limit};
use crate::state::ApiState;

/// Builds the request data from the state and the configuration. Reads each secret.
fn context(state: ApiState, config: &ApiConfig, shutdown: Shutdown) -> Result<Ctx> {
    config.validate()?;
    let auth = Authenticator::from_config(&config.principals, state.env())?;
    let chat = ChatOps::from_config(&config.chatops, &auth, state.env())?;
    Ok(Arc::new(AppContext {
        state,
        auth,
        limits: config.limits,
        streams: Arc::new(Semaphore::new(config.limits.max_streams)),
        shutdown,
        audit_head: Mutex::new(None),
        chat,
    }))
}

async fn unknown_path() -> ApiError {
    ApiError::NotFound("The path does not exist.".to_owned())
}

async fn unknown_method() -> ApiError {
    ApiError::MethodNotAllowed
}

fn build(ctx: &Ctx, config: &ApiConfig) -> Router {
    let mut router: Router<Ctx> = Router::new()
        .route("/healthz", get(healthz))
        .nest(API_BASE, api_router(ctx))
        .merge(chatops::chatops_router(ctx));
    if config.console {
        router = router.merge(console_router());
    }
    #[cfg(feature = "grpc")]
    {
        router = router.merge(crate::grpc::grpc_router(ctx));
    }
    router
        .fallback(|| async { unknown_path().await.into_response() })
        .method_not_allowed_fallback(|| async { unknown_method().await.into_response() })
        .layer(DefaultBodyLimit::max(config.limits.max_body_bytes))
        .layer(middleware::from_fn_with_state(ctx.clone(), time_limit))
        .layer(middleware::from_fn(security_headers))
        .with_state(ctx.clone())
}

/// Builds the router of the API: the REST routes, the console, and the ChatOps endpoints.
///
/// The function reads each secret that the configuration names through the environment
/// function of `state`. It starts no task. A live feed of this router ends only when the
/// client closes it. Use [`serve`] for a server that stops on a signal and that runs the
/// notification task.
///
/// # Errors
///
/// Returns [`Error::Config`] if the configuration is not valid or a secret is missing. The
/// message names the key or the environment variable. It never shows a secret.
pub fn router(state: ApiState, config: &ApiConfig) -> Result<Router> {
    let ctx = context(state, config, Shutdown::new())?;
    Ok(build(&ctx, config))
}

/// Runs the API server on the address in the configuration until `shutdown` is triggered.
///
/// The default address is `127.0.0.1:8080`. The server has no TLS. It refuses an address
/// that is not a loopback address, unless
/// [`ApiConfig::allow_non_loopback`] is `true`.
///
/// # Errors
///
/// Returns [`Error::Config`] if the configuration is not valid, and [`Error::Unavailable`]
/// if the server cannot listen on the address.
pub async fn serve(state: ApiState, config: ApiConfig, shutdown: Shutdown) -> Result<()> {
    config.validate()?;
    config.validate_bind()?;
    let listener = TcpListener::bind(config.bind).await.map_err(|error| {
        Error::Unavailable(format!(
            "the API server cannot listen on {}: {error}",
            config.bind
        ))
    })?;
    serve_on(listener, state, config, shutdown).await
}

/// Runs the API server on a listener that the caller made.
///
/// Use this function to listen on a port that the operating system selects, for example in
/// a test. [`ApiConfig::bind`] is not used.
///
/// On a trigger of `shutdown`, the server stops to accept connections, ends each live
/// feed, lets each open request complete, and stops the notification task.
///
/// # Errors
///
/// Returns [`Error::Config`] if the configuration is not valid, and [`Error::Other`] if
/// the server fails.
pub async fn serve_on(
    listener: TcpListener,
    state: ApiState,
    config: ApiConfig,
    shutdown: Shutdown,
) -> Result<()> {
    // A child signal ends the tasks of the server and not the tasks of the caller.
    let stop = shutdown.child();
    let ctx = context(state, &config, stop.clone())?;
    let app = build(&ctx, &config);
    // The task subscribes before the server starts, so a bus fault stops the start.
    let notifier = match Notifier::from_context(&ctx, &config.chatops.notifications)? {
        Some(notifier) => Some(tokio::spawn(notifier.subscribe().await?.run(stop.clone()))),
        None => None,
    };

    let address = listener.local_addr().ok();
    tracing::info!(?address, "the API server listens");
    let signal = stop.clone();
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async move { signal.wait().await })
        .await
        .map_err(|error| Error::other("run the API server", error));

    stop.trigger();
    let notified = match notifier {
        Some(task) => match task.await {
            Ok(result) => result,
            Err(error) => Err(Error::other("run the notification task", error)),
        },
        None => Ok(()),
    };
    served.and(notified)
}
