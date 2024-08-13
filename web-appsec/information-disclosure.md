# Information Disclosure

\


Most of these function calls are not sinks. But rather it maybe a vulnerability if any of the data returned is viewable to an attacker. If an attacker can see phpinfo() it is definitely a vulnerability.

```
phpinfo
posix_mkfifo
posix_getlogin
posix_ttyname
getenv
get_current_user
proc_get_status
get_cfg_var
disk_free_space
disk_total_space
diskfreespace
getcwd
getlastmo
getmygid
getmyinode
getmypid
getmyuid
extract    // Opens the door for register_globals attacks (see study in scarlet).
parse_str  // works like extract if only one argument is given.
putenv
ini_set
mail       // has CRLF injection in the 3rd parameter, opens the door for spam.
header     // on old systems CRLF injection could be used for xss or other purposes, now it is still a problem if they do a header("location: ..."); and they do not die();. The script keeps executing after a call to header(), and will still print output normally. This is nasty if you are trying to protect an administrative area.
proc_nice
proc_terminate
proc_close
pfsockopen
fsockopen
apache_child_terminate
posix_kill
posix_mkfifo
posix_setpgid
posix_setsid
posix_setuid
```

