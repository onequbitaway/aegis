# Repository guidelines

AEGIS is a defensive agentic security framework in Rust. Read `README.md` for the design and
`CONTRIBUTING.md` for the full rules.

## Rules

- Defensive only. Do not write offensive, exploitation, or counter-attack code. This rule
  includes payloads, stubs, and examples. If a task needs such code, stop and tell the user.
- Write all runtime code in Rust. Library code must not panic. Do not write `unsafe` code.
- Put each new crate in `crates/`. Add `[lints] workspace = true` to its `Cargo.toml`.
- Tests must not use the network or real credentials.
- Write documentation, commit bodies, and pull request text in STE100 style.
- Write commit subjects as Conventional Commits, 72 characters or fewer.

## Commands

`rust-toolchain.toml` pins the Rust toolchain. Run all four checks before you report that a
change is complete. CI runs the same commands.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```
