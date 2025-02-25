# DNS perf test
DNS-client-test program resolves domains from a file with a set number of requests per second. And it can save the results to files. The cache.data can be used in the dns-server-test program.
## Usage
```sh
Commands:
  Required parameters:
    -file /example.txt            Domains file path
    -DNS 0.0.0.0:00               DNS address
    -listen 0.0.0.0:00            Listen address
    -RPS 00000                    Request per second
  Optional parameters:
    -save                         Save DNS answer data to cache.data,
                                  DNS answer domains to out_domains.txt,
                                  DNS answer IPs to ips.txt
```
