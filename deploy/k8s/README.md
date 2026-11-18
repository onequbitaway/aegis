# Plain Kubernetes manifests

`aegis.yaml` has the manifests of AEGIS for a cluster with no Helm.

The Helm chart in [`../helm/aegis`](../helm/aegis) is the source. `aegis.yaml` is the
output of the chart with its default values, the release name `aegis`, and the namespace
`aegis`. Do not change the file by hand. The package workflow fails if the file is
different from the output of the chart.

Refer to [`../README.md`](../README.md#kubernetes) for the description of the objects and
of the settings.

## Apply the manifests

1. Build the image and push it to a registry that the cluster can read.
2. Make the namespace and the Secret with the API token:

   ```sh
   kubectl create namespace aegis
   kubectl --namespace aegis create secret generic aegis-credentials \
       --from-literal=operator-token="$(openssl rand -hex 32)"
   ```

3. Apply the manifests with the name of your image. The file names a placeholder image.

   ```sh
   sed 's#registry.example.com/aegis/aegis:0.1.0#registry.internal/aegis/aegis:0.1.0#' \
       deploy/k8s/aegis.yaml | kubectl --namespace aegis apply --filename -
   kubectl --namespace aegis rollout status deployment/aegis
   ```

For each other change, use the chart: change the values and render the manifests again.

## Render the manifests again

Run this command from the root of the repository after each change to the chart, or to
the directories `detections`, `policies`, and `playbooks`:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --volume "$PWD:/repo:ro" --workdir /repo \
    alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e \
    template aegis deploy/helm/aegis --namespace aegis > deploy/k8s/aegis.yaml
```

The command uses the Helm version of the package workflow, so that the output is the
same. With a Helm program on your computer, the command is
`helm template aegis deploy/helm/aegis --namespace aegis`. A different Helm version can
give different empty lines.
