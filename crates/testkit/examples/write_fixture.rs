//! Prints the attack log as JSON Lines.
//!
//! Run this command to write the repository file again after a change to the log:
//!
//! ```sh
//! cargo run -p aegis-testkit --example write_fixture > fixtures/artex_style_attack.jsonl
//! ```

use aegis_testkit::fixtures;

fn main() -> aegis_contracts::Result<()> {
    print!("{}", fixtures::to_jsonl(&fixtures::artex_style_attack())?);
    Ok(())
}
