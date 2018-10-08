# kcron
A utility for getting Kerberos credentials in scheduled jobs

This utility reduces the burden on Kerberos realm administrators while providing users with a secure way to run scheduled jobs without extracting personal credentials to a keytab.
 
It requires changes to KDC configuration. Provided KDC is properly configured, any principal user@REALM is able to create and destroy keytabs for principals of the form username/cron/host.domain@REALM

This utility can also be used to run scheduled jobs under any local account “username”, even if principal username@REALM does not exist. This is especially useful if local account “username” is accessed by multiple users. Kerberos administrator will first create principal username/cron/host.domain@REALM and provide initial password to the requestor. The requestor can then run kcroninit utility to create the keytab.

Kcron utility is designed for use with crontab. An example of scheduled job with kcron

1 * * * *  /usr/bin/kcron “/home/username/script.py”

This will execute script.py on the first minute of every hour with Kerberos credentials username/cron/host.domain@REALM, provided the keytab was previously created via kcroninit utility. Any permissions that are necessary to run script.py need to be granted to principal username/cron/host.domain@REALM

Changes to KDC configuration:
Add the following line to kadm5.acl file on your KDC

*@REALM                              acdim   *1/cron/*@REALM 

Followed by any flags that meet your needs, taking into account principal and ticket lifetimes. 

See the [documentation](https://github.com/scientificlinux/kcron/blob/master/doc/kcron.doc) folder for more information

