# Domain Fudgery

''Disclaimer'': Do not use this tool for malicious purposes. Ensure you have permission.

Fudges domains for social engineering or phishing. The tool generates a list of potential
domains using the following techniques:

1. Look-alike character substitution (e.g. replace "m" with "rn")
2. (Optional) 

## Passive Checks


## Active Checks

With the list of fudged domains, the tool then performs DNS lookups on the domains for 
the base domain and common subdomains (e.g. www). If the base domain's nameserver is not
resolvable, the domain is considered available.

The list of available domains is then 

## Installation

```
pip3 install -r requirements.txt
```

## Usage

```
domain-fudgery.py [options] [domain]
OPTIONS:

TLD Options:
    --country-code-tlds     check country code TLDs
    --original-tlds         check original TLDs (.com, .net, .org)
    --custom-tlds           check additional list of TLDS, comma separated

General Options:
    --file                  load domains from the given filename
                            one domain per line
    --no-active             use only passive checks
    --no-whois              do not perform whois checks
```


