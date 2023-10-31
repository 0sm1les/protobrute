# protobrute
Protobrute is a multithreaded brute forcer with automatic service detection.
## Usage
```
Usage of protobrute
  -auto
        auto detect protocols (limited support) (default true)
  -headers string
        headers to add to post request. format: 'key:value,key:value'
  -o string
        write valid credentials to a file
  -p string
        file containing password list
  -parent string
        post valid credentials to a remote host in json format
  -protocol string
        use a specific protocol
  -t int
        amount of hosts to target at once (default 1)
  -targets string
        file containing list of targets to brute force
  -u string
        file containing username list
```

## supported protocols
with autodetection:
- ssh
- vnc
- ftp
- mysql / mariadb
  
no autodetection:
- postgres
