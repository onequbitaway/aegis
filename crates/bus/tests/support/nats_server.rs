//! A disposable NATS server for the tests that the `docker-tests` feature enables.
//!
//! Tests that can share a server call [`NatsServer::shared`]. It uses the server in the
//! environment variable `AEGIS_TEST_NATS_URL`, or starts one container for the test binary.
//! Tests that restart the server, or that need a special server configuration, call
//! [`NatsServer::start`]. Those tests always need Docker.
//!
//! Each container has a unique name with the prefix `aegis-test-bus-`, a random free port on the
//! local host, and a limited life. The helper removes the container when the last test
//! that uses it ends.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The variable that holds the URL of an existing NATS server with JetStream.
pub const URL_VARIABLE: &str = "AEGIS_TEST_NATS_URL";
/// The variable that selects a different NATS image.
pub const IMAGE_VARIABLE: &str = "AEGIS_TEST_NATS_IMAGE";

const DEFAULT_IMAGE: &str = "nats:2.12-alpine";
const CONTAINER_PREFIX: &str = "aegis-test-bus-";
const NATS_PORT: u16 = 4222;
/// A container stops itself after this time, also when the test process cannot remove it.
const CONTAINER_LIFE_SECONDS: &str = "900";
/// The directory in the container that gets the files of [`ServerOptions::files`].
pub const CONFIG_DIRECTORY: &str = "/etc/aegis-test";
const START_ATTEMPTS: u32 = 5;
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const READY_POLL: Duration = Duration::from_millis(50);

/// The settings of a server that one test owns.
pub struct ServerOptions {
    /// The text of a NATS configuration file.
    pub config: Option<String>,
    /// More files for the directory [`CONFIG_DIRECTORY`]: the file name and the content.
    pub files: Vec<(String, Vec<u8>)>,
    /// Start the server with JetStream. The default is `true`.
    pub jetstream: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            config: None,
            files: Vec::new(),
            jetstream: true,
        }
    }
}

/// A NATS server with JetStream.
pub struct NatsServer {
    url: String,
    container: Option<Container>,
}

struct Container {
    name: String,
    port: u16,
}

impl Drop for Container {
    fn drop(&mut self) {
        match docker(&["rm", "--force", "--volumes", &self.name]) {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "cannot remove the container {}: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!("cannot remove the container {}: {error}", self.name),
        }
    }
}

impl NatsServer {
    /// Returns the server for the tests that can share one server.
    pub fn shared() -> Arc<Self> {
        static SHARED: Mutex<Weak<NatsServer>> = Mutex::new(Weak::new());
        let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(server) = shared.upgrade() {
            return server;
        }
        let server = Arc::new(match external_url() {
            Some(url) => Self {
                url,
                container: None,
            },
            None => Self::start(&ServerOptions::default()),
        });
        *shared = Arc::downgrade(&server);
        server
    }

    /// Starts a server in a new container that only the caller uses.
    ///
    /// # Panics
    ///
    /// Panics with an explanation when Docker is not available.
    pub fn start(options: &ServerOptions) -> Self {
        let mut last_error = String::new();
        for _ in 0..START_ATTEMPTS {
            match Container::start(options) {
                Ok(container) => {
                    let server = Self {
                        url: format!("nats://127.0.0.1:{}", container.port),
                        container: Some(container),
                    };
                    server.wait_until_ready();
                    return server;
                }
                Err(StartError::PortInUse(error)) => last_error = error,
                Err(StartError::Fatal(error)) => panic!("{}", no_server_message(&error)),
            }
        }
        panic!(
            "cannot find a free port for a NATS container after {START_ATTEMPTS} attempts: \
             {last_error}"
        );
    }

    /// The URL of the server.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Stops the server process and starts it again. Streams with file storage survive.
    pub fn restart(&self) {
        run_docker(&["restart", "--time", "1", &self.own_container().name]);
        self.wait_until_ready();
    }

    /// Stops the server process for a time. The connections stay open, but the server
    /// does not answer. [`NatsServer::resume`] lets the server continue.
    pub fn pause(&self) {
        run_docker(&["pause", &self.own_container().name]);
    }

    /// Lets a server continue after [`NatsServer::pause`].
    pub fn resume(&self) {
        run_docker(&["unpause", &self.own_container().name]);
    }

    fn own_container(&self) -> &Container {
        self.container
            .as_ref()
            .expect("only a server that the test started can stop and continue")
    }

    /// Waits until the server sends its greeting on the client port.
    fn wait_until_ready(&self) {
        let container = self.own_container();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, container.port));
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if greets(address) {
                return;
            }
            assert!(
                container.is_running(),
                "the NATS container {} stopped during its start. Its server configuration is \
                 probably not valid. Run the image with the same configuration to see the error.",
                container.name
            );
            if Instant::now() >= deadline {
                let logs = docker(&["logs", "--tail", "40", &container.name])
                    .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
                    .unwrap_or_default();
                panic!(
                    "the NATS container {} did not get ready in {READY_TIMEOUT:?}; its log:\n{logs}",
                    container.name
                );
            }
            std::thread::sleep(READY_POLL);
        }
    }
}

enum StartError {
    /// A different process took the port between the selection and the start.
    PortInUse(String),
    Fatal(String),
}

impl Container {
    /// Returns `true` if Docker says that the container runs or restarts.
    fn is_running(&self) -> bool {
        docker(&["inspect", "--format", "{{.State.Status}}", &self.name]).is_ok_and(|output| {
            let status = String::from_utf8_lossy(&output.stdout);
            output.status.success() && matches!(status.trim(), "running" | "restarting" | "created")
        })
    }

    fn start(options: &ServerOptions) -> Result<Self, StartError> {
        let image = std::env::var(IMAGE_VARIABLE).unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
        let port = free_port();
        let name = unique_name();
        let publish = format!("127.0.0.1:{port}:{NATS_PORT}");
        let config_path = format!("{CONFIG_DIRECTORY}/nats.conf");
        let mut arguments = vec![
            "create",
            "--rm",
            "--name",
            &name,
            "--label",
            "aegis.test=bus",
            "--publish",
            &publish,
            // `timeout` ends the server after a fixed time, so a container that a killed
            // test process leaves behind does not stay for long.
            "--entrypoint",
            "timeout",
            &image,
            CONTAINER_LIFE_SECONDS,
            "nats-server",
        ];
        if options.jetstream {
            arguments.push("--jetstream");
        }
        if options.config.is_some() {
            arguments.extend(["--config", &config_path]);
        }
        let created = docker(&arguments).map_err(|error| StartError::Fatal(error.to_string()))?;
        if !created.status.success() {
            return Err(StartError::Fatal(stderr(&created)));
        }
        // From here, `Drop` removes the container, also when a later step fails.
        let container = Self { name, port };

        let mut files = options.files.clone();
        if let Some(config) = &options.config {
            files.push(("nats.conf".to_owned(), config.clone().into_bytes()));
        }
        if !files.is_empty() {
            let directory = tempfile::tempdir().expect("a temporary directory");
            for (file_name, content) in &files {
                std::fs::write(directory.path().join(file_name), content).expect("write a file");
            }
            let source = format!("{}/.", directory.path().display());
            let target = format!("{}:{CONFIG_DIRECTORY}", container.name);
            run_docker(&["cp", &source, &target]);
        }

        let started = docker(&["start", &container.name])
            .map_err(|error| StartError::Fatal(error.to_string()))?;
        if started.status.success() {
            return Ok(container);
        }
        let error = stderr(&started);
        if error.contains("port is already allocated") || error.contains("address already in use") {
            Err(StartError::PortInUse(error))
        } else {
            Err(StartError::Fatal(error))
        }
    }
}

/// Returns the URL in [`URL_VARIABLE`], if the variable has a value.
pub fn external_url() -> Option<String> {
    std::env::var(URL_VARIABLE)
        .ok()
        .filter(|url| !url.trim().is_empty())
}

fn no_server_message(docker_error: &str) -> String {
    if external_url().is_some() {
        format!(
            "This test controls its own NATS server (it restarts the server, or it needs \
             special server settings). Thus, it needs Docker, also when {URL_VARIABLE} is set. \
             Docker said: {docker_error}"
        )
    } else {
        format!(
            "The `docker-tests` feature needs a NATS server. Start Docker, or set {URL_VARIABLE} \
             to the URL of a NATS server that has JetStream. Docker said: {docker_error}"
        )
    }
}

/// Runs `docker` and collects its output. An error means that the program did not start.
fn docker(arguments: &[&str]) -> std::io::Result<Output> {
    Command::new("docker").args(arguments).output()
}

/// Runs `docker` for a step that must succeed.
fn run_docker(arguments: &[&str]) {
    let output = docker(arguments).unwrap_or_else(|error| panic!("cannot run docker: {error}"));
    assert!(
        output.status.success(),
        "docker {arguments:?} failed: {}",
        stderr(&output)
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_owned()
}

/// Asks the operating system for a port that is free at this moment.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("a free port on the local host")
        .port()
}

fn unique_name() -> String {
    format!("{CONTAINER_PREFIX}{}", unique_token())
}

/// Returns a token that no other test of this machine uses. It is valid as a subject token
/// and as a part of a stream name.
pub fn unique_token() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanoseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .subsec_nanos();
    format!("t{}x{count}x{nanoseconds:08x}", std::process::id())
}

/// Returns `true` if a NATS server sends its greeting on this address.
fn greets(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .is_err()
    {
        return false;
    }
    let mut greeting = [0_u8; 5];
    stream.read_exact(&mut greeting).is_ok() && &greeting == b"INFO "
}
