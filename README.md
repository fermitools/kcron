# kcron
A utility for getting Kerberos credentials into non-interactive environments.

This utility reduces the burden on Kerberos realm administrators while providing users with a secure way to run daemons and scheduled jobs without extracting personal credentials to a keytab.
 
It requires changes to KDC configuration. Provided KDC is properly configured, any principal `user@REALM` is able to create and destroy keytabs for principals of the form `username/cron/host.domain@REALM`

This utility can also be used to run scheduled jobs under any local account `username`, even if principal `username@REALM` does not exist. This is especially useful if local account `username` is accessed by multiple users.

## User workflow

Kerberos administrator will first create principal `username/cron/host.domain@REALM` and provide initial password to the requestor. The requestor can then run `kcroninit` utility to create the keytab.

Run `kcroninit` to generate your kcron keytab (in `/var/kerberos/krb5/user/${EUID}/client.keytab`) once your principal exists and you have the required password.

When your user/job/daemon requires a Kerberos ticket but does not have one, the Kerberos libraries will automatically import the ticket.
The identity is selected based on either `~/.k5identity` or `slot 1` from your kcron keytab (in `/var/kerberos/krb5/user/${EUID}/client.keytab` following the traditional `kinit -kt` matching rules).

Runtime usage is automatic if you do not have a valid Kerberos ticket.

Setup your cron job following traditional cron rules.  A `kcron` prefix command is no longer required.

## Changes to KDC configuration
 Add the following line to kadm5.acl file on your KDC

> `*@REALM                              acdim   *1/cron/*@REALM `

Followed by any flags that meet your needs, taking into account principal and ticket lifetimes. 

## Runtime Requirements

  * MIT Kerberos 1.11 (or later) or Heimdal Kerberos 8 (or later)

Optional Runtime Requirements:

  * libcap - for use of system capibilities rather than suid
  * libseccomp - for dropping any unused system calls

You are strongly encouraged to run with SELinux or AppArmor in enforcing mode to further protect the system from unknown exploits using this binaries enhanced privilege set.

## Build Requirements

  * CMake 3.14 or later
  * C Compiler that understand C-2011
  * for manpages `asciidoc`

Optional Build Requirements:

  * landlock headers - for filesystem level isolation
  * libcap headers - for use of system capibilities rather than suid
  * libseccomp headers - for dropping any unused system calls

You may change the `/var/kerberos/krb5/user/` to an alternate location at build time by setting `-DCLIENT_KEYTAB_DIR=/usr/local/var/kerberos/krb5/user/` on `cmake`.

## To Build

```bash
 <unpack sources and change into source directory>
 mkdir build
 cd build
 cmake ..
 make
 make test
```

The `Makefile` is not setting either SUID or CAPIBILITIES on the binary.  This is by design.

See the [documentation](https://github.com/fermitools/kcron/tree/main/doc) folder for more information.
