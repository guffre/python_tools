# ssh_user_enum

This is PoC code for CVE-2018-15473 (OpenSSH < 7.7). The advantage of using *my* PoC code is that it allows threading, unlike the vast majority (or all?) other PoC codes you find out there using paramiko.

The reason mine allows threading is that it doesn't clobber the functionality of paramiko by temporarily replacing internal functions (looking at you, add_boolean PoC's).

## Usage
    ./sshuser <username> <host> <port>
    
    There are two other functions included in the file:
    
        def ssh_wordlist_usernames(host,wordlist,threads=16,port=22)
    
    and
        
        def ssh_bruteforce_usernames(host,minlength=1,maxlength=8,threads=16,port=22)

    These allow using dictionaries or simply bruteforcing, as the names suggest.

## Requirements

    paramiko
