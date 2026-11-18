//! The shutdown signal for long-running loops.
//!
//! A [`Shutdown`] is a handle to one signal. All clones of a handle share the signal. Give
//! a clone or a [child](Shutdown::child) to each loop. The loop stops when
//! [`Shutdown::wait`] completes.
//!
//! ```
//! use aegis_core::Shutdown;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! async fn run(shutdown: Shutdown) -> u32 {
//!     let mut ticks = 0;
//!     loop {
//!         tokio::select! {
//!             () = shutdown.wait() => return ticks,
//!             () = tokio::task::yield_now() => ticks += 1,
//!         }
//!     }
//! }
//!
//! let shutdown = Shutdown::new();
//! let worker = tokio::spawn(run(shutdown.clone()));
//! shutdown.trigger();
//! assert!(worker.await.is_ok());
//! # }
//! ```

use std::io;
use std::sync::mpsc::{SyncSender, sync_channel};

use aegis_contracts::{Error, Result};
use tokio_util::sync::CancellationToken;

/// The name of the thread that waits for the stop requests of the operating system.
const LISTENER_THREAD_NAME: &str = "aegis-stop-signals";

/// A handle to a shutdown signal.
///
/// A clone shares the signal of the original. After [`Shutdown::trigger`], the signal stays
/// triggered.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    /// Makes a new signal that is not triggered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Triggers the signal. All waiters of this handle, of its clones, and of its children
    /// continue. A second call has no effect.
    pub fn trigger(&self) {
        self.token.cancel();
    }

    /// Returns `true` after the signal is triggered.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Waits until the signal is triggered. Completes immediately if it is triggered already.
    ///
    /// The future is cancel-safe.
    pub async fn wait(&self) {
        self.token.cancelled().await;
    }

    /// Makes a child signal.
    ///
    /// A trigger of this handle also triggers the child. A trigger of the child does not
    /// trigger this handle. Use a child to stop one subsystem and keep the others.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            token: self.token.child_token(),
        }
    }

    /// Starts a listener that triggers this signal when the process gets a stop request.
    ///
    /// On Unix, a stop request is SIGINT (Ctrl-C) or SIGTERM. On other systems, it is
    /// Ctrl-C.
    ///
    /// The listener is a thread of its own. Thus you can call this function with or without
    /// a Tokio runtime, and the runtime does not need its IO driver. The function blocks
    /// the thread for a short time. On Unix, the signal handlers are in effect when the
    /// function returns. The listener thread ends when the signal is triggered.
    ///
    /// If the listener fails later, it writes an error event and triggers the signal. A
    /// process that cannot receive a stop request must not continue.
    ///
    /// The signal handlers stay in effect until the process stops. After the first stop
    /// request, a second SIGINT or SIGTERM does not stop the process. Set a time limit for
    /// the shutdown work in the binary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the operating system refuses the listener thread or the
    /// signal handlers.
    pub fn listen_for_signals(&self) -> Result<()> {
        let shutdown = self.clone();
        let (ready_sender, ready) = sync_channel(1);
        std::thread::Builder::new()
            .name(LISTENER_THREAD_NAME.to_owned())
            .spawn(move || listen(&shutdown, &ready_sender))
            .map_err(|error| Error::other("start the stop signal listener", error))?;
        match ready.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::other("install the stop signal handlers", error)),
            Err(error) => Err(Error::other("install the stop signal handlers", error)),
        }
    }
}

/// Runs the listener thread. Sends the result of the setup to `ready` one time.
///
/// The thread has a Tokio runtime of its own, because the stop requests of Tokio need an IO
/// driver, and the runtime of the caller possibly has none.
fn listen(shutdown: &Shutdown, ready: &SyncSender<io::Result<()>>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return report(ready, Err(error)),
    };
    runtime.block_on(async {
        let mut signals = match StopSignals::register() {
            Ok(signals) => signals,
            Err(error) => return report(ready, Err(error)),
        };
        report(ready, Ok(()));
        tokio::select! {
            received = signals.receive() => {
                match received {
                    Ok(signal) => tracing::info!(signal, "stop signal received"),
                    Err(error) => tracing::error!(%error, "the stop signal listener failed"),
                }
                shutdown.trigger();
            }
            () = shutdown.wait() => {}
        }
    });
}

/// Sends the result of the listener setup to the caller of [`Shutdown::listen_for_signals`].
fn report(ready: &SyncSender<io::Result<()>>, result: io::Result<()>) {
    // The caller waits for this message, so the send fails only if the caller is gone.
    if let Err(unsent) = ready.send(result)
        && let Err(error) = unsent.0
    {
        tracing::error!(%error, "the stop signal listener did not start");
    }
}

/// The stop requests of the operating system.
#[cfg(unix)]
struct StopSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl StopSignals {
    /// Installs the signal handlers. Call this function in a Tokio runtime.
    fn register() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Waits for one stop request and returns its name.
    async fn receive(&mut self) -> io::Result<&'static str> {
        let (received, name) = tokio::select! {
            received = self.interrupt.recv() => (received, "SIGINT"),
            received = self.terminate.recv() => (received, "SIGTERM"),
        };
        received.map(|()| name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("the {name} stream closed"),
            )
        })
    }
}

/// The stop requests of the operating system.
#[cfg(not(unix))]
struct StopSignals;

#[cfg(not(unix))]
impl StopSignals {
    /// Does nothing. The Ctrl-C handler is installed at the first call of `receive`.
    fn register() -> io::Result<Self> {
        Ok(Self)
    }

    /// Waits for one stop request and returns its name.
    async fn receive(&mut self) -> io::Result<&'static str> {
        tokio::signal::ctrl_c().await.map(|()| "Ctrl-C")
    }
}
