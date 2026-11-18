# Repository guidelines

AEGIS is a defensive agentic security framework in Rust. Read `README.md` for the design and
`CONTRIBUTING.md` for the full rules.

## Rules

- Defensive only. Do not write offensive, exploitation, or counter-attack code. This rule
  includes payloads, stubs, and examples. If a task needs such code, stop and tell the user.
- Write all runtime code in Rust. Library code must not panic. Do not write `unsafe` code.
- Put each new crate in `crates/`. Add `[lints] workspace = true` to its `Cargo.toml`.
- `crates/contracts` is frozen. Do not change it in a workstream change. Send a change request
  to the project lead.
- A crate talks to a different subsystem only through `aegis-contracts`. Use `aegis-testkit`
  for in-memory implementations in tests.
- Take shared dependencies from `[workspace.dependencies]` in the root `Cargo.toml`.
- Tests must not use the network or real credentials.
- Write documentation, commit bodies, and pull request text in STE100 style.
- Write commit subjects as Conventional Commits, 72 characters or fewer.
- Do not add AI or agent attribution to a commit or a pull request. Do not write a
  `Co-Authored-By` trailer for a tool, a "Generated with" line, or a session link.
- Do not put the name of a tool or an agent in a branch name.

## Commands

`rust-toolchain.toml` pins the Rust toolchain. Run all four checks before you report that a
change is complete. CI runs the same commands.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```
