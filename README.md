## What is PwnKit
PwnKit exploits a vulnerability in the SUID-root program /usr/bin/pkexec, allowing unprivileged users to gain full root privileges on Linux systems. This vulnerability has existed since 2009 and was publicly disclosed in January 2022.

## pwnkit_safety_check.c
PwnKit (CVE-2021-4034) Safe Checker This tool performs read-only checks and does not attempt exploitation. 

## Build/Compile
```
$ cd
$ gcc -O2 -Wall -Wextra PwnKit_Check.c -o Pwnkit_Check
```
## Run
```
./PwnKit_Check
PwnKit (CVE-2021-4034) Safe Checker
This tool performs read-only checks and does not attempt exploitation.
```
