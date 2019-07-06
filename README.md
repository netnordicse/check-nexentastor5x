### Introduction
This check is written for Icinga2 / Nagios standard with exit levels between 0-3
Use it with a read only api user on your NexentaStor5 Appliance

This has been tested on a NexentaStor5 5.1.1 (API v1.1.1)

### Key features
* Monitoring alerts on different severities: minor, major and critical

### Requirements
* Python 3

### Setup
```
pip install -r requirements.txt
```

### Usage
##### Print help file:
```
# python check_nexentastor5x.py -h
```

##### Check for faulty alerts
```
# python check_nexentastor5x.py -H my-nexentastor-11.sds.local -P 8443 -u my-api-user -p my-api-password -c alert -s major -f true
```
