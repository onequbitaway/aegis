# Contributing to AEGIS

Thank you for your interest in AEGIS. This document tells you how to contribute.

## Ground rules

- AEGIS ships defensive modules only. Do not submit offensive, exploitation, or counter-attack
  code. This rule includes payloads, stubs, and examples.
- Obey the [Code of Conduct](CODE_OF_CONDUCT.md).
- Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Before you start

- Search the open issues and pull requests for the same topic.
- For a large change, open an issue first. Agree on the design before you write the code.
- Keep each pull request to one concern.

## Set up your environment

1. Install [rustup](https://rustup.rs).
2. Clone the repository.
3. Install the pinned toolchain.

   ```sh
   rustup toolchain install
   ```

4. Build the workspace.

   ```sh
   cargo build --workspace
   ```

## Run the checks

Run these commands before you open a pull request. CI runs the same commands.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

## Code rules

- Write all runtime code in Rust.
- Put each new crate in `crates/`. Add `[lints] workspace = true` to its `Cargo.toml`.
- `crates/contracts` holds the frozen contracts between subsystems. Open an issue before you
  change it.
- A crate talks to a different subsystem only through `aegis-contracts`.
- Library code must not panic. Do not use `unwrap`, `expect`, `panic!`, `todo!`, or
  `unimplemented!` outside tests. The workspace lints reject them.
- Do not write `unsafe` code. The workspace lints forbid it.
- Use `thiserror` for the error types of a library crate. Use `anyhow` only in binaries.
- Write a documentation comment for each public item.
- Add a dependency only when it is necessary. Commit the changes to `Cargo.lock`.

## Test rules

- Each crate must have unit tests. Each public contract must have an integration test.
- Tests must not use the network or real credentials. Use mocks or recorded data.
- Make sure that a new test fails without your change.
- Do not remove or weaken a test to make the checks pass.

## Commits and pull requests

- Write commit subjects as [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/),
  for example `feat(detection): add the sign-in burst detector`.
- Keep the subject to 72 characters or fewer.
- Fill in all sections of the pull request template.
- Add a line to `CHANGELOG.md` below `Unreleased` for each change that a user can see.

## Writing style

Write documentation, commit bodies, and pull request text in ASD Simplified Technical English
([STE100](https://www.asd-ste100.org/)) style.

- Write one idea in each sentence.
- Keep sentences short: 20 words or fewer for instructions, 25 words or fewer for descriptions.
- Keep paragraphs to six sentences or fewer.
- Use the active voice. Write "The router selects a model", not "A model is selected".
- Use simple words. Use one word for one meaning, and use it the same way each time.
- Write instructions as commands. Write "Run `cargo test`", not "You should run the tests".
- Use lists for steps and for three or more related items.

## License

AEGIS uses the [MIT License](LICENSE). When you contribute, you agree to license your
contribution under the same license.
