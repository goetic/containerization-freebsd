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

pub(crate) const APPLY: Script = Script(include_str!("scripts/apply.sh"));
pub(crate) const CLAIM: Script = Script(include_str!("scripts/claim.sh"));
pub(crate) const COPY_RESOLV_CONF: Script = Script(include_str!("scripts/copy-resolv-conf.sh"));
pub(crate) const DATASET_IO: Script = Script(include_str!("scripts/dataset-io.sh"));
pub(crate) const DECOMPRESS: Script = Script(include_str!("scripts/decompress.sh"));
pub(crate) const DISK_DEVICE: Script = Script(include_str!("scripts/disk-device.sh"));
pub(crate) const DROP: Script = Script(include_str!("scripts/drop.sh"));
pub(crate) const FIRST_BOOT_DONE: Script = Script(include_str!("scripts/first-boot-done.sh"));
pub(crate) const GONE: Script = Script(include_str!("scripts/gone.sh"));
pub(crate) const INTERFACES: Script = Script(include_str!("scripts/interfaces.sh"));
pub(crate) const LEASE: Script = Script(include_str!("scripts/lease.sh"));
pub(crate) const LIMIT: Script = Script(include_str!("scripts/limit.sh"));
pub(crate) const MOUNT_SHARE: Script = Script(include_str!("scripts/mount-share.sh"));
pub(crate) const NAT: Script = Script(include_str!("scripts/nat.sh"));
pub(crate) const REMOVE_RESOLV_CONF: Script = Script(include_str!("scripts/remove-resolv-conf.sh"));
pub(crate) const RESOLVE: Script = Script(include_str!("scripts/resolve.sh"));
pub(crate) const ROUTED: Script = Script(include_str!("scripts/routed.sh"));
pub(crate) const UNMOUNT: Script = Script(include_str!("scripts/unmount.sh"));
