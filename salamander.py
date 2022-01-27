#!/usr/bin/python
import re
import os
import sys
import subprocess
import platform
from subprocess import PIPE

def banner():
    print(""""_____  ___   _       ___  ___  ___  ___   _   _______ ___________
/  ___|/ _ \ | |     / _ \ |  \/  | / _ \ | \ | |  _  \  ___| ___ \\
\ `--./ /_\ \| |    / /_\ \| .  . |/ /_\ \|  \| | | | | |__ | |_/ /
 `--. \  _  || |    |  _  || |\/| ||  _  || . ` | | | |  __||    /
/\__/ / | | || |____| | | || |  | || | | || |\  | |/ /| |___| |\ \\
\____/\_| |_/\_____/\_| |_/\_|  |_/\_| |_/\_| \_/___/ \____/\_| \_|
Survey Secure Protect""")
    try:
        a = sys.argv[1]
    except:
        print("\n usage: ./salamander <output_file>")
        print("        If <output_file> is \"-\", will only output interesting data")
        sys.exit()

banner()
known_exes = {"which": "which"}

def run(command):
    command = command.split(" ")
    command[0] = exe(command[0])
    command = " ".join(command)
    p = subprocess.Popen([command],stdin=PIPE,stdout=PIPE,stderr=PIPE,shell=True)
    out,err = p.communicate()
    return out[:-1]

def exe(exe_name,known_exes=known_exes):
    #This checks if the executable is on the system or not, then saves the path into known_exes dictionary
    #If the executable doesnt exist, it maps the name to /dev/null and raises a warning
    if known_exes.has_key(exe_name):
        return known_exes[exe_name]
    exepath = run("which {}".format(exe_name))
    if len(exepath) == 0:
        if exe_name == "netstat":
            return exe("ss", known_exes)
        print(' * WARNING\n * "{}" not found on system'.format(exe_name))
        exepath = "/dev/null"
    known_exes[exe_name] = exepath
    return exepath

def init_system():
    #Checks if system is using init,systemd,upstart
    init = run("cat /proc/1/comm")
    if "init" in init:
        if re.findall("upstart",run("/sbin/init --version"),re.IGNORECASE):
            return "upstart"
        else:
            return "init"
    else:
        return init

def all_data_to_file():
    #Writes all data to file specified in sys.argv[1]
    with open(sys.argv[1],"w") as f:
        for command in info:
            f.write(" * SALAMANDER: {} information section\n".format(command))
            command_info = info[command].replace("\n","\n"+command+":: ")
            f.write(command + ":: " + command_info + "\n")
    print("done.")

info = {
    "uname":run("uname -a"),
    "lsblk":run("lsblk"),
    "blkid":run("blkid"),
    "mount":run("mount"),
    "fdisk":run("fdisk -l"),
    "cpu":run("grep name /proc/cpuinfo"),
    "parted":run("parted -l"),
    "arch":run("getconf LONG_BIT"),
    "last":run("last"),
    "w":run("w"),
    "suid_files":run("find / -uid 0 -perm /4000 -ls"),
    "ps":run("ps aux"),
    "os_info1":run("cat /etc/*vers*"),
    "os_info2":run("cat /etc/*rele*"),
    "netstat":run("netstat -anop"),
    "ifconfig":run("ifconfig -a"),
    "ip":run("ip a"),
    "lsof":run("lsof"),
    "uptime":run("uptime"),
    "arp":run("arp -a -v"),
    "route":run("route -n -v"),
    "passwd":run("cat /etc/passwd"),
    "dmesg":run("dmesg"),
    "iptables":run("iptables -nvL"),
    "groups":run("cat /etc/group"),
    "cronjobs1":run("grep -HP ^[^#].* /etc/*cron*"),
    "cronjobs2":run("grep -HP ^[^#].* /etc/*cron*/*"),
    "cronjobs3":run("grep -HP ^[^#].* /var/spool/cron/*/*"),
    "kernel":platform.system(), #Linux
    "dist1":platform.dist()[0], #('Ubuntu', '16.04', 'xenial')
    "dist2":platform.dist()[1],
    "dist3":platform.dist()[2],
    "init":init_system(),
    "interfaces":run("ifconfig -a -s"),
    "interfaces2":run("ip link"),
    "lsmod":run("lsmod -nvL"),
    "memory":run("free -lh")
    #"":run("")
}

def interesting_ttys(process_info):
    #TTYs that have a shell
    return re.findall(".*[pt]t[sy].*[sS][hH]",process_info,re.IGNORECASE)

def interesting_suid(suid_files):
    #SUID files that are known priv-esc vulnerable
    matches = []
    for suid in suid_files.split("\n"):
        for program in ["python","perl","sh","nano","vi","ed","pico","nmap"]:
            if program in suid.lower():
                matches.append(suid)
    return matches

if __name__ == '__main__':
    print(" *** SYSTEM INFO ***")
    print("""
     [+] Kernel: {arch}-bit {kernel}
     [+] Distro: {dist1}-{dist2}
     [+] Codename: {dist3}
     [+] Uptime: {uptime}
     [+] Init System: {init}

     [+] Logged-in users:
     {w}
    """.format(**info))

    listening = run("netstat -nopltu")
    if len(info["interfaces"]) < 10:
        info["interfaces"] = info["interfaces2"]
    print(" *** NETWORK INFO ***")
    print("""
     [+] Interfaces:
    {interfaces}

     [+] Listening:
    {listening}

    """.format(listening=listening,**info))

    print(" *** DISK INFORMATION ***")
    print("""
     [+] Hard Drives:
     {lsblk}

     [+] Partitions:
     {parted}

     [+] Memory:
     {memory}
    """.format(**info))

    print(" *** INTERESTING FILES/PROCESSES ***")
    print("\n [+] Vulnerable SUID files:")
    #for n in interesting_suid(info["suid_files"]):
    for n in info["suid_files"].split("\n"):
        print(" [*] {}".format(n))
    print("\n [+] Shell TTYs:")
    for tty in interesting_ttys(info["ps"]):
        print(" [*] {}".format(tty))
    
    if sys.argv[1] != "-":
        all_data_to_file()
