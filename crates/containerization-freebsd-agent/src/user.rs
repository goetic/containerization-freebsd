//! Resolves the user a process runs as by looking up its User in the root's
//! `/etc/passwd` and `/etc/group`, as runc and Containerization's `vminitd`
//! do.

use containerization_freebsd_protocol::User;
use std::io;
use std::path::Path;

/// A user's ids and home directory.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ids {
  pub(crate) uid: u32,
  pub(crate) gid: u32,
  /// Supplementary groups.
  pub(crate) groups: Vec<u32>,
  pub(crate) home: String,
}

struct Account<'a> {
  name: &'a str,
  uid: u32,
  gid: u32,
  home: &'a str,
}

struct Group<'a> {
  name: &'a str,
  gid: u32,
  members: Vec<&'a str>,
}

/// Looks up `user` in the files under `root`, a directory in the guest. A
/// missing file counts as empty; a file whose path leads out of `root` is
/// refused.
pub(crate) fn look_up(user: &User, root: &Path) -> io::Result<Ids> {
  let passwd = read(root, "etc/passwd")?;
  let group = read(root, "etc/group")?;

  resolve(user, &passwd, &group).map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))
}

/// Resolves `user` as runc does. A name must be listed in passwd; a numeric
/// uid need not be, and an unlisted uid gets gid 0 and home `/`. The
/// supplementary groups are those that list the user as a member, unless
/// `user.group` is set: then it replaces the primary group and no listed
/// groups are added. `user.groups` are always added.
fn resolve(user: &User, passwd: &str, group: &str) -> Result<Ids, String> {
  let uid = user.name.parse::<u32>().ok();
  let account = accounts(passwd).find(|account| match uid {
    Some(uid) => account.uid == uid,
    None => account.name == user.name,
  });
  let (uid, gid, home, name) = match (account, uid) {
    (Some(account), _) => (account.uid, account.gid, account.home, Some(account.name)),
    (None, Some(uid)) => (uid, 0, "/", None),
    (None, None) => return Err(format!("no user {:?} in /etc/passwd", user.name)),
  };
  let listed: Vec<Group> = groups(group).collect();

  let (gid, mut groups) = match &user.group {
    Some(group) => (gid_of(group, &listed)?, Vec::new()),
    None => {
      let member = |group: &&Group| name.is_some_and(|name| group.members.contains(&name));
      (
        gid,
        listed
          .iter()
          .filter(member)
          .map(|group| group.gid)
          .collect(),
      )
    }
  };
  for group in &user.groups {
    let gid = gid_of(group, &listed)?;
    if !groups.contains(&gid) {
      groups.push(gid);
    }
  }

  Ok(Ids {
    uid,
    gid,
    groups,
    home: home.to_string(),
  })
}

/// Parses `group` as a gid, or else looks up the gid of the group so named.
fn gid_of(group: &str, listed: &[Group]) -> Result<u32, String> {
  if let Ok(gid) = group.parse() {
    return Ok(gid);
  }
  listed
    .iter()
    .find(|listed| listed.name == group)
    .map(|listed| listed.gid)
    .ok_or_else(|| format!("no group {group:?} in /etc/group"))
}

/// The entries of a passwd(5) file, skipping comments, NIS entries and
/// malformed lines.
fn accounts(passwd: &str) -> impl Iterator<Item = Account<'_>> {
  entries(passwd).filter_map(|fields| match fields[..] {
    [name, _, uid, gid, _, home, _] => Some(Account {
      name,
      uid: uid.parse().ok()?,
      gid: gid.parse().ok()?,
      home,
    }),
    _ => None,
  })
}

/// The entries of a group(5) file, skipped as in `accounts`.
fn groups(group: &str) -> impl Iterator<Item = Group<'_>> {
  entries(group).filter_map(|fields| match fields[..] {
    [name, _, gid, members] => Some(Group {
      name,
      gid: gid.parse().ok()?,
      members: members
        .split(',')
        .filter(|member| !member.is_empty())
        .collect(),
    }),
    _ => None,
  })
}

fn entries(text: &str) -> impl Iterator<Item = Vec<&str>> {
  text
    .lines()
    .filter(|line| !line.is_empty() && !line.starts_with(['#', '+', '-']))
    .map(|line| line.split(':').collect())
}

/// Reads `path` under `root`, returning an empty string if the file does not
/// exist.
fn read(root: &Path, path: &str) -> io::Result<String> {
  let root = root.canonicalize()?;
  let file = match root.join(path).canonicalize() {
    Ok(file) => file,
    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
    Err(error) => return Err(error),
  };

  if file.starts_with(&root) {
    std::fs::read_to_string(file)
  } else {
    Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("/{path} leads out of {}", root.display()),
    ))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const PASSWD: &str = "\
# $FreeBSD$
root:*:0:0:Charlie &:/root:/bin/sh
operator:*:2:5:System &:/:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
broken:*:x:1:::
+:::::::
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
";
  const GROUP: &str = "\
wheel:*:0:root
operator:*:5:root
www:*:80:
staff:*:20:root,www
nogroup:*:65533:
nobody:*:65534:
";

  fn user(name: &str) -> User {
    User {
      name: name.into(),
      ..User::default()
    }
  }

  fn ids(uid: u32, gid: u32, groups: &[u32], home: &str) -> Ids {
    Ids {
      uid,
      gid,
      groups: groups.to_vec(),
      home: home.into(),
    }
  }

  #[test]
  fn takes_a_named_users_ids_home_and_the_groups_that_list_them() {
    assert_eq!(
      resolve(&user("www"), PASSWD, GROUP),
      Ok(ids(80, 80, &[20], "/nonexistent"))
    );
    assert_eq!(
      resolve(&user("root"), PASSWD, GROUP),
      Ok(ids(0, 0, &[0, 5, 20], "/root"))
    );
  }

  #[test]
  fn takes_a_uid_as_its_listed_user_or_alone() {
    assert_eq!(
      resolve(&user("80"), PASSWD, GROUP),
      Ok(ids(80, 80, &[20], "/nonexistent"))
    );
    assert_eq!(resolve(&user("4242"), PASSWD, GROUP), Ok(ids(4242, 0, &[], "/")));
    assert_eq!(resolve(&user("4242"), "", ""), Ok(ids(4242, 0, &[], "/")));
  }

  #[test]
  fn refuses_a_name_that_is_not_listed() {
    let error = resolve(&user("ghost"), PASSWD, GROUP).unwrap_err();

    assert!(error.contains("ghost"), "{error}");
    assert!(resolve(&user("root"), "", GROUP).is_err());
  }

  #[test]
  fn a_group_given_replaces_the_users_own_and_those_that_list_them() {
    let by_name = User {
      group: Some("nogroup".into()),
      ..user("www")
    };
    let by_gid = User {
      group: Some("4343".into()),
      ..user("www")
    };

    assert_eq!(
      resolve(&by_name, PASSWD, GROUP),
      Ok(ids(80, 65533, &[], "/nonexistent"))
    );
    assert_eq!(resolve(&by_gid, PASSWD, GROUP), Ok(ids(80, 4343, &[], "/nonexistent")));
  }

  #[test]
  fn adds_more_groups_by_name_or_gid_once_each() {
    let more = User {
      groups: vec!["operator".into(), "20".into(), "4444".into()],
      ..user("www")
    };

    assert_eq!(
      resolve(&more, PASSWD, GROUP),
      Ok(ids(80, 80, &[20, 5, 4444], "/nonexistent"))
    );
  }

  #[test]
  fn refuses_a_group_name_that_is_not_listed() {
    let unlisted = User {
      groups: vec!["ghosts".into()],
      ..user("www")
    };

    let error = resolve(&unlisted, PASSWD, GROUP).unwrap_err();
    assert!(error.contains("ghosts"), "{error}");
  }

  #[test]
  fn reads_a_roots_files_and_takes_a_missing_one_as_empty() {
    let root = std::env::temp_dir().join(format!("cfbsd-agent-user-{}", std::process::id()));
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/passwd"), PASSWD).unwrap();

    let found = look_up(&user("www"), &root);
    let numeric = look_up(&user("4242"), &root.join("etc"));
    std::fs::remove_dir_all(&root).unwrap();

    assert_eq!(found.unwrap(), ids(80, 80, &[], "/nonexistent"));
    assert_eq!(numeric.unwrap(), ids(4242, 0, &[], "/"));
  }

  #[test]
  fn refuses_a_file_that_leads_out_of_the_root() {
    let root = std::env::temp_dir().join(format!("cfbsd-agent-escape-{}", std::process::id()));
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("etc/passwd")).unwrap();

    let refused = look_up(&user("4242"), &root);
    std::fs::remove_dir_all(&root).unwrap();

    let error = refused.unwrap_err();
    assert!(error.to_string().contains("leads out of"), "{error}");
  }
}
