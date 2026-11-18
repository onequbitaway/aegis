# AEGIS examples

Each directory is a configuration set that you can load and run. All examples are
defensive. In each example, each response action is a dry run, so no example changes
your environment.

| Directory | Contents | Needs |
| --- | --- | --- |
| [`offline-demo`](offline-demo/README.md) | The service with the web console, on the recorded attack log. It shows an approval. | Nothing more. No model, no database, no network. |
| [`local-model`](local-model/README.md) | The agents and detection tier 2 with a local model. | An OpenAI-compatible model server on the same host. |
| [`entra`](entra/README.md) | Microsoft Entra ID as the source, and Microsoft Graph for the identity actions. | A tenant and two application registrations. |
| [`device-code-phishing`](device-code-phishing/README.md) | One more detection pack and playbook pair, with sample events. | Nothing more. |

## Before you start

1. Build the program. Run this command in the root of the repository.

   ```sh
   cargo build -p aegis-cli --locked
   ```

2. Put the program in the path of your terminal.

   ```sh
   export PATH="$PWD/target/debug:$PATH"
   ```

3. Run each command of an example in the root of the repository.

## Rules for all examples

- A relative path in a configuration file starts at the directory of that file. The
  examples use the detection pack, the policies, and the playbooks of the repository.
- Each example writes its audit log and its checkpoints to its `data` directory. Git
  ignores these files.
- The examples use example identifiers only: `example.com` names, documentation
  addresses, and placeholder tenant identifiers. No file holds a secret.
- Check a configuration before you run it: `aegis config check --config <file>`.

Refer to [`docs/configuration.md`](../docs/configuration.md) for each key of the
configuration file.
