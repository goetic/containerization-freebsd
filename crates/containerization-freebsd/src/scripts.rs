//! Shell scripts the library runs in the guest. Each `scripts/*.sh` documents
//! its positional parameters. Lint with `shellcheck src/scripts/*.sh`.
//! `user-data.sh` has no constant here: `prepare` writes it to the seed for
//! nuageinit to run.

/// A script for the guest's sh(1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Script(&'static str);

impl Script {
  /// The argv for `sh -c` with `args` as `$1`, `$2`, …; `$0` is `sh`.
  pub(crate) fn argv<'a>(self, args: &[&'a str]) -> Vec<&'a str> {
    let mut argv = vec!["sh", "-c", self.0, "sh"];
    argv.extend_from_slice(args);
    argv
  }
}

pub(crate) const ADDRESS: Script = Script(include_str!("scripts/address.sh"));
pub(crate) const APPLY: Script = Script(include_str!("scripts/apply.sh"));
pub(crate) const CLAIM: Script = Script(include_str!("scripts/claim.sh"));
pub(crate) const DECOMPRESS: Script = Script(include_str!("scripts/decompress.sh"));
pub(crate) const EPAIR: Script = Script(include_str!("scripts/epair.sh"));
pub(crate) const LEASE: Script = Script(include_str!("scripts/lease.sh"));
pub(crate) const ROUTED: Script = Script(include_str!("scripts/routed.sh"));
