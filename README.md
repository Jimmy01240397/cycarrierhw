# cycarrierhw

## Build
Clone and cd into cycarrierhw
```bash
make
```
```
$ ls -al bin/
total 5516
drwxr-xr-x 2 root root       0 May 17 08:54 .
drwxr-xr-x 2 root root       0 May 17 08:54 ..
-rwxr-xr-x 1 root root 5644288 May 17 08:54 cycarrierhw
-rwxr-xr-x 1 root root      29 May 17 08:54 .env
```

## Run
1. Goto [https://www.virustotal.com/gui/user/<username\>/apikey](https://www.virustotal.com/gui/sign-in) and copy your API key to `.env` `VIRUSTOTALAPIKEY`
![image](https://github.com/Jimmy01240397/cycarrierhw/assets/57281249/4e88ab83-81d0-433d-ae52-8ac80878ea3b)

2. Goto https://www.abuseipdb.com/account/api and copy your API key to `.env` `ABUSEIPDB`

```
VIRUSTOTALAPIKEY=
ABUSEIPDB=
```

3. Run `./cycarrierhw` to get help

```
$ ./cycarrierhw
Usage: ./bin/cycarrierhw <domain or ip>
```
