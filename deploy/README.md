# Deploy AEGIS

This directory has the packages of AEGIS: a container image, Docker Compose files, a Helm
chart, and plain Kubernetes manifests. All packages run the program `aegis` of the crate
`aegis-cli`. AEGIS is defensive only.

All packages start with safe settings. Each response action is a dry run, and no model
is configured. AEGIS changes nothing in your environment until you change the
configuration.

## Contents

- [Options](#options)
- [Feature matrix](#feature-matrix)
- [The image](#the-image)
- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [Air-gap procedure](#air-gap-procedure)
- [Hardening notes](#hardening-notes)
- [What is not covered](#what-is-not-covered)
- [The package workflow](#the-package-workflow)

## Options

| Option | Files | Use |
| --- | --- | --- |
| Image | `docker/aegis/Dockerfile` | The base of all other options. One static binary on an empty base image. |
| Database image | `docker/postgres/` | PostgreSQL with Apache AGE and pgvector. Refer to [`docker/postgres/README.md`](docker/postgres/README.md). |
| Compose stack | `compose/compose.yaml` | One Docker host with AEGIS, PostgreSQL, and NATS JetStream. |
| Compose stack with a local model | `compose/compose.yaml` and `compose/local-model.env` | The same stack with a model server on the host. It needs no internet. |
| Compose, monitoring only | `compose/compose.monitoring-only.yaml` | One container. No database, no NATS server, and no HTTP server. |
| Helm chart | `helm/aegis/` | Kubernetes. One AEGIS process, with an optional external PostgreSQL and NATS. |
| Plain manifests | `k8s/aegis.yaml` | The chart with its default values, for a cluster with no Helm. |

The only prerequisite for the image and the Compose files is Docker with Buildx and
Compose. Run each command of this document from the root of the repository, unless the
text gives a different directory.

## Feature matrix

The build argument `AEGIS_FEATURES` selects the Cargo features of the binary.

| Function | Image `full` | Image `monitoring-only` |
| --- | --- | --- |
| Cargo features of `aegis-cli` | `postgres`, `plugins`, `otlp`, `api` (the defaults) | None (`--no-default-features`) |
| Ingestion, detection, agents, playbooks, policy | Yes | Yes |
| In-process bus and in-memory storage | Yes | Yes |
| NATS JetStream bus | Yes | Yes |
| File audit log | Yes | Yes |
| Models (OpenAI-compatible and Anthropic adapters) | Yes | Yes |
| PostgreSQL storage and PostgreSQL audit log | Yes | No |
| WebAssembly connector plugins | Yes | No |
| OpenTelemetry trace export | Yes | No |
| Operator API, web console, and ChatOps | Yes | No |
| gRPC services (Cargo feature `grpc`) | No | No |

The modules of the configuration select the subsystems that a process runs. The Cargo
features select the subsystems that the binary can run. A configuration that needs a
feature that the binary does not have stops the process with an error.

| Setting | Compose stack | Compose with a local model | Compose, monitoring only | Helm, default values | Helm, example for external services |
| --- | --- | --- | --- | --- | --- |
| Image | `full` | `full` | `monitoring-only` | `full` | `full` |
| Bus | NATS JetStream | NATS JetStream | In the process | In the process | External NATS |
| Storage | PostgreSQL | PostgreSQL | In memory | In memory | External PostgreSQL |
| Audit log | File in a volume | File in a volume | File of the session | File in a volume claim | PostgreSQL |
| Model | None | Ollama | None | None | None |
| Operator API | Loopback address of the host | Loopback address of the host | None | Service in the cluster | Service in the cluster |
| Response actions | Dry run | Dry run | None | Dry run | Dry run |
| Source of events | The recorded attack log | The recorded attack log | The recorded attack log | None | None |

## The image

### Build the image

```sh
# The full image, for the platform of this computer.
docker build --file deploy/docker/aegis/Dockerfile --tag aegis:local .

# The monitoring-only image.
docker build --file deploy/docker/aegis/Dockerfile --tag aegis:monitoring-only \
    --build-arg AEGIS_FEATURES=monitoring-only .

# The two platforms in one image.
docker buildx build --file deploy/docker/aegis/Dockerfile \
    --platform linux/amd64,linux/arm64 --tag aegis:local --load .
```

The build needs only Docker. It needs the internet for the base images, the Alpine
packages, and the crates.

- The build stages run on the platform of the build computer and compile for the target
  platform. A build for a different processor needs no emulator.
- The Rust version of the build image must be the version in `rust-toolchain.toml`. If
  the two are different, the build stops with an error that names the two versions.
- Cargo builds with `--locked`. The dependencies come from `Cargo.lock`.
- The build stops if the binary is not for the target platform, or if it is not
  statically linked.
- The dependencies are in a layer of their own. A change to the source code of AEGIS
  compiles only the AEGIS crates.

| Build argument | Values | Default |
| --- | --- | --- |
| `AEGIS_FEATURES` | `full`, `monitoring-only` | `full` |

A different value stops the build with an error.

To use a different Rust version, change `rust-toolchain.toml` and the tag and the digest
of the `rust` image in the Dockerfile together.

### Contents of the image

| Path | Contents |
| --- | --- |
| `/aegis` | The program. It is the entry point. |
| `/etc/ssl/certs/ca-certificates.crt` | The certificate authorities that the TLS clients trust. |
| `/usr/share/licenses/aegis/LICENSE` | The MIT License. |
| `/etc/aegis` | Empty. A volume for the configuration, the policy, the detection pack, and the playbooks. |
| `/var/lib/aegis` | Empty. A volume for the audit log and the checkpoints of the sources. It is the working directory. |
| `/plugins` | Empty. A volume for the connector plugins. |
| `/tmp` | Empty. `aegis demo` and `aegis monitor` write temporary files here. |

- The base image is `scratch`. The image has no shell, no package manager, and no C
  library.
- The user is the numeric user `65532:65532`. The image has no `/etc/passwd`.
- The default command is `run --config /etc/aegis/aegis.toml`.
- The image declares no port. The operator API listens on the address in `api.bind`.
- The label `org.opencontainers.image.description` names the feature set of the image.

| Image | Platform | Binary | Image, compressed | Type of the binary |
| --- | --- | --- | --- | --- |
| `full` | `linux/amd64` | 47.0 MB | 17.4 MB | Statically linked, position independent (static PIE) |
| `full` | `linux/arm64` | 37.6 MB | 15.8 MB | Statically linked |
| `monitoring-only` | `linux/amd64` | 24.2 MB | 9.3 MB | Statically linked, position independent (static PIE) |
| `monitoring-only` | `linux/arm64` | 19.8 MB | 8.7 MB | Statically linked |

The image is the binary plus 180 kB of certificates. These sizes are for version 0.1.0.

### Run the image

```sh
# The demonstration: replay the recorded attack log as a dry run with no model.
docker run --rm aegis:local demo

# The same, with the limits that the Compose files and the chart use.
docker run --rm --read-only --tmpfs /tmp:mode=1777 --cap-drop ALL \
    --security-opt no-new-privileges --network none aegis:local demo

# Write a starter directory to a volume, check it, and run the service.
docker volume create aegis-config
docker run --rm --volume aegis-config:/etc/aegis aegis:local init --dir /etc/aegis
docker run --rm --volume aegis-config:/etc/aegis aegis:local \
    config check --config /etc/aegis/aegis.toml
docker run --rm --read-only --volume aegis-config:/etc/aegis:ro \
    --volume aegis-data:/var/lib/aegis \
    --env AEGIS__AUDIT__PATH=/var/lib/aegis/audit.jsonl \
    --env AEGIS__INGEST__CHECKPOINT_DIR=/var/lib/aegis/checkpoints \
    aegis:local
```

- The starter configuration writes its audit log and its checkpoints to
  `/etc/aegis/data`. The two variables of the last command move them to `/var/lib/aegis`,
  so that `/etc/aegis` can be read-only.
- A directory of the host that you mount must be readable by the user `65532`. The
  directory for `/var/lib/aegis` must also be writable by that user.
- The operator API has no TLS and refuses an address that is not a loopback address. In
  a container, set `bind = "0.0.0.0:8080"` and `allow_non_loopback = true` in the `[api]`
  section, and publish the port only on the loopback address of the host:
  `--publish 127.0.0.1:8080:8080`.

### Examine the binary

```sh
docker create --name aegis-binary aegis:local
docker cp aegis-binary:/aegis ./aegis
docker rm --volumes aegis-binary
file ./aegis
```

The image declares three volumes. `docker rm --volumes` and `docker run --rm` remove the
volumes that Docker makes for a container with no volume option.

The build is reproducible on one build computer. The base images have digests, the Rust
version is pinned, the dependencies come from `Cargo.lock`, and the binary has no time
stamp. Two builds on one computer, the second with `--no-cache`, give the same binary
byte for byte.

These conditions can change the binary:

- The build does not pin the versions of the Alpine packages `clang`, `lld`, `gcc`, and
  `musl-dev`. A later build can get a newer C compiler for the C code of the
  dependencies.
- The processor of the build computer has an effect. A build of the `linux/amd64` binary
  on an amd64 computer and a build of it on an arm64 computer give different files. The
  two files work.

The image has the time of the build in its layers. Thus the digest of the image is
different for each build.

## Docker Compose

Go to the directory `deploy/compose` for all commands of this section. The Compose files
read files of the repository, so they need a checkout.

### Start the stack

1. Make the file `.env` and set the three secrets. Each secret must have a random value
   of its own.

   ```sh
   cp .env.example .env
   openssl rand -hex 32    # Run it three times. Put one value in each secret.
   ```

2. Build the images and start the stack. The command returns when all services are
   healthy.

   ```sh
   docker compose up --build --detach --wait
   ```

3. Examine the result.

   ```sh
   docker compose ps
   docker compose logs aegis
   docker compose exec aegis /aegis audit verify --path /var/lib/aegis/audit.jsonl
   docker compose exec aegis /aegis audit show --path /var/lib/aegis/audit.jsonl --limit 20
   docker compose exec postgres psql --username aegis --dbname aegis \
       --command 'select count(*) from aegis.incidents'
   ```

4. Open `http://127.0.0.1:8080/` and enter the value of `AEGIS_TOKEN_OPERATOR`. Or send
   a request to the REST API:

   ```sh
   token="$(sed -n 's/^AEGIS_TOKEN_OPERATOR=//p' .env)"
   curl --header "Authorization: Bearer $token" http://127.0.0.1:8080/api/v1/incidents
   curl --header "Authorization: Bearer $token" http://127.0.0.1:8080/api/v1/audit/verification
   ```

At the first start, AEGIS reads the recorded attack log `fixtures/artex_style_attack.jsonl`
one time. It makes one critical incident and runs the playbooks as dry runs.

### What the stack has

| Service | Image | Data | Network |
| --- | --- | --- | --- |
| `aegis` | The full image | Volume `aegis-data`: the audit log and the checkpoints | `backplane` and `edge`. Port 8080 on `127.0.0.1` of the host. |
| `postgres` | `docker/postgres` | Volume `postgres-data` | `backplane`. No port on the host. |
| `nats` | `nats`, with JetStream and a client token | Volume `nats-data` | `backplane`. No port on the host. |
| `ollama` | `ollama/ollama`, only with the profile `local-model` | Volume `ollama-models` | `backplane`. No port on the host. |

- The network `backplane` is internal: it has no route to the internet. PostgreSQL,
  NATS, and the model server are only on this network. The network `edge` gives AEGIS
  its published port and its connections to the systems that it protects.
- The service `aegis` has a read-only root file system, no Linux capability, the option
  `no-new-privileges`, and the user `65532`.
- Each service has a health check. AEGIS starts after PostgreSQL and NATS are healthy.
- The health check of `aegis` verifies the hash chain of the audit log file. The image
  has no HTTP client for a request to `/healthz`. The check reads the full file, so its
  time increases with the size of the file.

### Configure the stack

| File | Contents |
| --- | --- |
| `.env` | The secrets, the port of the API on the host, and the image names. Git ignores the file. |
| `aegis.toml` | The configuration of AEGIS. It has no secret. |
| `nats.conf` | The configuration of the NATS server. It has no secret. |
| `local-model.env` | The overlay for the profile `local-model`. It has no secret. |

- `compose.yaml` gives each secret to AEGIS as an environment variable. A variable with
  the prefix `AEGIS__` sets one key of the configuration: `AEGIS__STORAGE__URL` sets
  `storage.url`.
- The container gets the directories `policies`, `detections`, and `playbooks` of the
  repository as read-only directories below `/etc/aegis`. To use your own files, change
  the left side of these lines in `compose.yaml`.
- To read your own sources, replace the `[[sources]]` table in `aegis.toml`.
- To let AEGIS change your environment, read the README files of `aegis-app`,
  `aegis-respond`, and `aegis-policy` first. Then change `dry_run` and `playbooks` in the
  `[response]` and `[agents]` sections.
- Check a changed configuration before you start AEGIS again. The command needs a
  stopped `aegis` service, because one process writes one audit file:

  ```sh
  docker compose stop aegis
  docker compose run --rm --no-deps aegis config check --config /etc/aegis/aegis.toml
  docker compose up --detach --wait
  ```

### Upgrade the stack

1. Make a backup of the database and of the audit log.

   ```sh
   docker compose exec -T postgres pg_dump --username aegis --format custom aegis > aegis.dump
   docker compose cp aegis:/var/lib/aegis/audit.jsonl ./audit.jsonl
   ```

2. Get the new version of the repository.
3. Build the images again and start the stack. AEGIS runs the database migrations when
   it starts.

   ```sh
   docker compose up --build --detach --wait
   ```

4. Examine the health and the audit chain as in [Start the stack](#start-the-stack).

To go to a different PostgreSQL major version, restore the backup in a new volume. A
data directory of one major version does not start with a different major version.

### Stop and remove the stack

```sh
# Stop the containers and keep the data.
docker compose down

# Stop the containers and remove the volumes with all data.
docker compose down --volumes

# Remove the images.
docker image rm aegis:local aegis-postgres:local
```

With the profile `local-model`, give the two environment files to each command, also to
`down`.

### The profile `local-model`

The profile adds the model server Ollama and points the `[model]` section of AEGIS at
it. The model server is only on the internal network, so it cannot download a model.
Load the model into the volume first.

1. On a computer with the internet, download the model into the volume of the stack.
   The volume name starts with the project name, `aegis`.

   ```sh
   docker compose --env-file .env --env-file local-model.env create ollama
   docker run --detach --name aegis-model-load --volume aegis_ollama-models:/root/.ollama \
       ollama/ollama:0.40.15@sha256:0e59999e0e8f9fd4e704bd788a89b7e4cad399367fb1365f8c102ac662288761
   docker exec aegis-model-load ollama pull llama3.1:8b
   docker rm --force aegis-model-load
   ```

   For a computer with no internet, refer to [Air-gap procedure](#air-gap-procedure).

2. Start the stack with the overlay file.

   ```sh
   docker compose --env-file .env --env-file local-model.env up --build --detach --wait
   ```

3. Make sure that the model server has the model and that AEGIS uses it.

   ```sh
   docker compose --env-file .env --env-file local-model.env exec ollama ollama list
   docker compose --env-file .env --env-file local-model.env logs ollama
   ```

- `local-model.env` sets `COMPOSE_PROFILES=local-model` and the keys of
  `[model.providers.local]` and `[model.routes]`. To use a different model, change
  `AEGIS__MODEL__PROVIDERS__LOCAL__CHAT_MODEL` in that file.
- To avoid the two `--env-file` options, set `COMPOSE_ENV_FILES=.env,local-model.env` in
  your shell.
- The Compose file gives the model server no GPU. A model on a processor with no
  accelerator is slow.
- The time limit of one model request is 60 seconds (`model.providers.local.timeout`).
  If the model does not answer in that time, the agents use their deterministic paths.
  Keep this limit shorter than the time limit of one agent task, which is 120 seconds
  (`agents.limits.task_timeout_seconds`). If not, a slow answer makes the task fail.

### The monitoring-only variant

```sh
docker compose --file compose.monitoring-only.yaml up --build
```

The service runs one monitoring session: `aegis monitor` on the recorded attack log. It
prints each detection and each incident, prints a summary, and stops with status 0. The
container has no network. The variant needs no file `.env`.

- For JSON Lines output, run the session with a different format:

  ```sh
  docker compose --file compose.monitoring-only.yaml run --rm aegis --format json monitor \
      --config /etc/aegis/aegis.toml --events /etc/aegis/events/artex_style_attack.jsonl
  ```

- To monitor your own sources continuously, put your `[[sources]]` in
  `aegis.monitoring-only.toml`. Then, in `compose.monitoring-only.yaml`, use the command
  `run --config /etc/aegis/aegis.toml`, set `restart: unless-stopped`, and remove the
  line `network_mode: none` if a source reads from the network. `aegis run` prints no
  detection. Read the audit log:

  ```sh
  docker compose --file compose.monitoring-only.yaml exec aegis /aegis audit show \
      --path /var/lib/aegis/audit.jsonl
  ```

- To remove the variant:

  ```sh
  docker compose --file compose.monitoring-only.yaml down --volumes
  ```

## Kubernetes

The chart `helm/aegis` runs one AEGIS process as a Deployment.

| Object | Function |
| --- | --- |
| Deployment | One pod. The strategy is `Recreate`: the old pod stops before the new pod starts. |
| ConfigMap `aegis` | `aegis.toml`, made from the values. It has no secret. |
| ConfigMap `aegis-starter` | The starter files: the default policy, the detection pack `aegis-identity`, and the sample playbooks. |
| ServiceAccount | It has no role. The pod gets no token. |
| Service | The operator API, as `ClusterIP`. |
| PersistentVolumeClaim | `/var/lib/aegis`: the audit log and the checkpoints. |
| NetworkPolicy | Permits connections to the operator API, DNS queries, and the egress rules of the values. |
| Ingress | Optional. The default is off. |

**One replica.** The file audit log has one writer, and the state of the detection engine
is in the memory of one process. A second pod cannot share that state. The chart refuses
`replicaCount` larger than 1.

### Before you install

1. Build the image and push it to a registry that the cluster can read. The project
   publishes no image at this time.
2. Make the namespace and the Secret. The chart reads all credentials from one Secret
   that you make. It makes no Secret.

   ```sh
   kubectl create namespace aegis
   kubectl --namespace aegis create secret generic aegis-credentials \
       --from-literal=operator-token="$(openssl rand -hex 32)"
   ```

### Install the chart

```sh
helm upgrade --install aegis deploy/helm/aegis --namespace aegis \
    --set image.repository=registry.example.com/aegis/aegis --set image.tag=0.1.0
kubectl --namespace aegis rollout status deployment/aegis
kubectl --namespace aegis port-forward service/aegis 8080:8080
```

Then open `http://127.0.0.1:8080/` and enter the token of the Secret.

The chart has links to the directories `detections`, `policies`, and `playbooks` of the
repository. Thus Helm needs the full checkout. `helm package deploy/helm/aegis` makes an
archive that has copies of these files and needs no checkout.

### The values

`helm/aegis/values.yaml` describes each value. These are the most important values:

| Value | Default | Meaning |
| --- | --- | --- |
| `image.repository`, `image.tag`, `image.digest` | A placeholder repository, the chart `appVersion` | The image. A digest has priority over the tag. |
| `credentials.existingSecret` | `aegis-credentials` | The Secret with all credentials. |
| `api.enabled` | `true` | The operator API. The probes use `GET /healthz`. With `false`, the pod has no probe. |
| `api.principals` | One principal, `operator@example.com` | The principals of the API, with the Secret key of each token. |
| `storage.kind` | `memory` | `memory` or `postgres`. |
| `audit.kind` | `file` | `file` or `postgres`. |
| `bus.kind` | `memory` | `memory` or `nats`. |
| `config.response.dryRun`, `config.agents.dryRun` | `true` | With `true`, each action is a dry run. |
| `config.response.playbooks` | `dry_run` | `off`, `dry_run`, or `live`. |
| `config.starterFiles` | `true` | Put the starter files in `/etc/aegis`. |
| `config.extraToml` | Empty | More tables for `aegis.toml`, for example `[[sources]]` and `[model.providers.local]`. |
| `config.aegisToml` | Empty | The full text of `aegis.toml`. It replaces the file that the chart makes. |
| `extraEnv`, `extraVolumes`, `extraVolumeMounts` | Empty | More variables and files for the container, for example the client secret of a source. |
| `persistence.enabled`, `persistence.size` | `true`, `1Gi` | The claim for `/var/lib/aegis`. |
| `networkPolicy.egress` | Empty | The connections that the pod can open. The default permits only DNS. |
| `networkPolicy.ingressFrom` | The pods of the namespace | The peers that can connect to the operator API. |
| `ingress.enabled` | `false` | An Ingress for the operator API. |
| `resources` | 100m CPU and 128Mi memory requested, 1Gi memory limit | The resources of the container. |

`/etc/aegis` is one read-only directory. To use your own policy, detection pack, or
playbooks, mount them at a different path with `extraVolumes` and `extraVolumeMounts`,
and give the absolute paths in `config.policy.paths`, `config.detection.pack`, and
`config.response.playbookDir`.

### An external PostgreSQL and NATS

`helm/aegis/examples/external-postgres-nats.values.yaml` is a set of values for an
external PostgreSQL server and an external NATS server with JetStream.

1. Make the Secret with the three keys. The database must have the `age` and `vector`
   extensions. Refer to [`docker/postgres/README.md`](docker/postgres/README.md).

   ```sh
   kubectl --namespace aegis create secret generic aegis-credentials \
       --from-literal=database-url='postgres://aegis:PASSWORD@db.example.com:5432/aegis?sslmode=verify-full' \
       --from-literal=nats-credential='NATS_PASSWORD' \
       --from-literal=operator-token="$(openssl rand -hex 32)"
   ```

2. Copy the example file. Set the addresses of the servers in `bus.nats.urls` and in
   `networkPolicy.egress`.
3. Install the chart with the file:

   ```sh
   helm upgrade --install aegis deploy/helm/aegis --namespace aegis --values my-values.yaml
   ```

- A NetworkPolicy accepts addresses and labels, not host names. Each external server
  needs one egress rule with its address.
- The NATS password and the NATS token must have only letters and digits.
- With `audit.kind: postgres` and `bus.kind: nats`, `/var/lib/aegis` holds only the
  checkpoints of the sources.

### Upgrade and remove

```sh
# Upgrade. The pod stops and starts again. AEGIS runs the database migrations at the start.
helm upgrade --install aegis deploy/helm/aegis --namespace aegis --values my-values.yaml

# Remove. The claim with the audit log stays.
helm uninstall aegis --namespace aegis

# Remove the audit log and the checkpoints also.
kubectl --namespace aegis delete persistentvolumeclaim aegis-data
```

Before an upgrade, make a backup of the database. The image has no `tar` program, so
`kubectl cp` cannot copy the audit log. Read the audit records through the API
(`GET /api/v1/audit`), or make a snapshot of the volume.

### Plain manifests

`k8s/aegis.yaml` is the output of `helm template` with the default values, the release
name `aegis`, and the namespace `aegis`. The chart is the source. Do not change the file
by hand. Refer to [`k8s/README.md`](k8s/README.md).

## Air-gap procedure

AEGIS needs no internet at run time. This procedure moves the images, a model, and the
files of the repository to a network with no internet.

### On a computer with the internet

1. Build the images. If the target hosts have a different processor, add
   `--platform linux/amd64` or `--platform linux/arm64` to the commands of this
   procedure.

   ```sh
   docker build --file deploy/docker/aegis/Dockerfile --tag aegis:local .
   docker build --tag aegis-postgres:local deploy/docker/postgres
   ```

2. Pull the other images of the Compose stack by their tags. `docker save` needs a tag:
   an image that Docker pulled by its digest has no tag.

   ```sh
   docker pull nats:2.12.15-alpine
   docker pull ollama/ollama:0.40.15
   ```

3. Write all images to one file.

   ```sh
   docker save --output aegis-images.tar \
       aegis:local aegis-postgres:local nats:2.12.15-alpine ollama/ollama:0.40.15
   ```

4. Download the model and write the model store to a file. The commands use the model
   server image, so they need no other image.

   ```sh
   docker volume create aegis-model-export
   docker run --detach --name aegis-model-load --volume aegis-model-export:/root/.ollama \
       ollama/ollama:0.40.15
   docker exec aegis-model-load ollama pull llama3.1:8b
   docker rm --force aegis-model-load
   docker run --rm --entrypoint tar --volume aegis-model-export:/root/.ollama:ro \
       --volume "$PWD:/out" ollama/ollama:0.40.15 \
       --create --file /out/ollama-models.tar --directory /root/.ollama .
   docker volume rm aegis-model-export
   ```

5. Write the repository to a file.

   ```sh
   git archive --format tar --output aegis-repository.tar HEAD
   ```

6. For Kubernetes, make the chart archive. It has copies of the starter files.

   ```sh
   helm package deploy/helm/aegis
   ```

7. Record the SHA-256 digest of each file, and move the files and the digests to the
   target network.

### On the host with no internet

1. Compare the SHA-256 digest of each file with the recorded digest.
2. Load the images.

   ```sh
   docker load --input aegis-images.tar
   ```

3. Extract the repository, go to `deploy/compose`, and make the file `.env`.
4. Put the file `ollama-models.tar` in that directory, and load the model into the
   volume of the stack.

   ```sh
   docker compose --env-file .env --env-file local-model.env create ollama
   docker compose --env-file .env --env-file local-model.env run --rm --no-deps \
       --entrypoint tar --volume "$PWD/ollama-models.tar:/tmp/ollama-models.tar:ro" \
       ollama --extract --file /tmp/ollama-models.tar --directory /root/.ollama
   ```

5. Start the stack. Do not build: the build needs the internet.

   ```sh
   docker compose --env-file .env --env-file local-model.env up --no-build --detach --wait
   ```

- `compose.yaml` names the NATS image and the model server image with a tag and a digest.
  A Docker engine with the containerd image store keeps the digest of a loaded image, and
  then finds the image. If your engine does not find an image by its digest, or if the
  tag has a different digest, make a file `compose.override.yaml` that names the images
  by tag only:

  ```yaml
  services:
    nats:
      image: nats:2.12.15-alpine
    ollama:
      image: ollama/ollama:0.40.15
  ```

- For Kubernetes, push the loaded image to the registry of the target network, and
  install the chart archive with `image.repository` set to that registry.
- With no model, leave out `local-model.env`, the model server image, and the model file.

## Hardening notes

The packages apply these limits. Keep them when you change a file.

- **Dry run.** Each package starts with `response.dry_run = true`,
  `agents.dry_run = true`, and `response.playbooks = "dry_run"`.
- **No secret in a file of the repository.** Secrets come from `.env` (Compose) or from
  a Secret that you make (Kubernetes). The stack does not start with a secret that has
  no value.
- **User and file system.** The container runs as the user `65532` with a read-only root
  file system, no Linux capability, and no privilege escalation. The chart also sets the
  seccomp profile `RuntimeDefault`.
- **Network.** The Compose stack publishes only the operator API, and only on the
  loopback address of the host. The NetworkPolicy of the chart refuses each connection
  that the values do not permit.
- **No shell.** The image has no shell. `docker exec` and `kubectl exec` can run only
  `/aegis`.

Do these tasks before you use a package for production:

- **TLS for the operator API.** The API has no TLS. Put a proxy with TLS before it. On
  Kubernetes, configure TLS in the Ingress. Do not publish the port on a different
  address than a loopback address without such a proxy.
- **TLS for PostgreSQL and NATS.** The Compose stack uses no TLS on its internal network,
  and AEGIS writes a warning about it. For a server on a different host, use
  `sslmode=verify-full` in the database URL and `tls://` in the NATS URL.
- **A database role with fewer privileges.** The Compose stack connects as the role that
  owns the database. Refer to "Roles and privileges" in the README of `aegis-storage`.
- **NATS permissions.** The Compose stack uses one token with all permissions. Refer to
  "NATS permissions" in the README of `aegis-bus`.
- **Your policy.** Read `policies/README.md`. You own the policy that permits or denies
  each action.
- **Tokens.** Give each person a principal and a token of their own. Change a token when
  a person leaves.
- **Backups.** Make backups of the PostgreSQL database and of the audit log. Keep a copy
  of the audit log on a different system.
- **Resources.** Set limits for memory and processor time for each Compose service. The
  chart sets them for the pod.
- **Image updates.** Each base image has a digest. Build the images again when a base
  image or a dependency has a security update.

Known limits of the packages:

- On `linux/arm64`, the binary is not position independent. The Rust target
  `aarch64-unknown-linux-musl` of Rust 1.99.1 does not make a static position-independent
  executable. On `linux/amd64`, the binary is a static position-independent executable.
- The image has no health command. The Compose health check verifies the audit log
  file. The chart uses HTTP probes, and it has no probe when `api.enabled` is `false`.
- The Compose services `postgres`, `nats`, and `ollama` start as the user `root` of
  their images. `postgres` changes to the user `postgres`. `nats` and `ollama` have no
  Linux capability.

## What is not covered

- **High availability.** AEGIS runs as one process. The packages have no second replica
  and no failover.
- **PostgreSQL and NATS for production.** The Compose stack has one PostgreSQL server
  and one NATS server with no replication, no TLS, and no backup schedule. The chart
  installs no PostgreSQL and no NATS.
- **A published image and a published chart.** The workflow builds and tests the image.
  It pushes nothing. There is no signature and no software bill of materials.
- **gRPC.** The images do not have the Cargo feature `grpc`.
- **A GPU for the model server.** The Compose file gives the model server no GPU.
- **Metrics.** AEGIS exports traces with OpenTelemetry. The packages have no metrics
  endpoint and no dashboard.
- **A test on a Kubernetes cluster.** The workflow lints and renders the chart and
  checks the manifests against the Kubernetes schemas. It installs the chart on no
  cluster.
- **Other platforms.** The image is for `linux/amd64` and `linux/arm64` only.
- **The licenses of the dependencies.** The image has the license of AEGIS. It does not
  have the license texts of the crates that the binary contains.

## The package workflow

`.github/workflows/package.yml` runs for each pull request and for each push to `main`.
It pushes no image and uses no secret.

| Job | Steps |
| --- | --- |
| Images and Compose stacks | Builds the full image, the monitoring-only image, and the database image, with the layer cache of GitHub Actions. Examines the user and the type of the binary. Runs `aegis demo` in the image. Checks the configuration of the chart and the overlay of the profile `local-model` with the binary. Starts the Compose stack, waits for the health checks, and checks the incident in the API and in PostgreSQL and the audit chain. Runs the monitoring-only variant. |
| Helm chart | Lints the chart, renders it, checks the manifests against the Kubernetes schemas, and compares `k8s/aegis.yaml` with the output of the chart. Makes sure that the chart refuses a second replica. |

The workflow downloads no model. It does not start the model server.

Helm has no official image. The workflow runs Helm from the image `alpine/helm` and
kubeconform from the image of its project. Each image has a tag and a digest.
