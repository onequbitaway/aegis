<!--
Write in STE100 style (CONTRIBUTING.md). Use short sentences, the active voice, and one idea
in each sentence.
-->

## Summary

<!-- What changed and why. -->

## Scope

<!-- The crates and areas that this change touches. -->

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
- [ ] I added or changed tests for the behavior that changed.
- [ ] I updated `CHANGELOG.md` and the documentation, if applicable.
- [ ] This change contains no offensive, exploitation, or counter-attack code.

## Related issues

<!-- For example: Fixes #123 -->
