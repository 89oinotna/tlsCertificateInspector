# tlsCertificateInspector

Simple **TLS certificate** inspector that log the certificates that are:
* **Invalid**: Before or After the certificate validity time
* **Self-Signed**: The Issuer is the same as the Subject

## Description

### TLS
TLS protocol operate above the transport level and it allows a safe communication from src to dst (end-to-end) on TCP/IP network providing a private, authenticated and reliable connection.

### Self-Signed certificate
With self signed certificate we identify certificate that is signed by the same entity whose identity it certifies.
The field that we want to analyze are:
* **Issuer**: The entity who provide the verification
* **Subject**: The entity verified by the certificate 

### Invalid certificate
Each TLS certificate has a temporal validity specified in the validity fields:
* **Not Before**: The certificate is not valid before this datetime
* **Not After**: The certificate is not valid before this datetime

## Prerequisites

To use this software you need:
* [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) that lets you capture or read packets
* [PyShark](https://github.com/KimiNewt/pyshark) which is a python tshark wrapper

## Usage
_**Root privileges are required based on your tshark configuration.**_

``` 
[sudo] python3 main.py [-h] [-i INTERFACE] [-l] [-t TIMEOUT] [-mp MAX_PACKET] [-fi INPUT_FILE] [-fo OUTPUT_FILE]
               
``` 

Arguments:
Flag | Store | Description
------------ | ------------- | -------------
 -h, --help | |  show this help message and exit
 -i | INTERFACE | Interface from which to capture (Default eth0)
 -l | | Enables live capture
 -t | TIMEOUT | Specify live sniff timeout in seconds (Default 0 means unlimited)
 -mp | MAX_PACKET | Maximum packet i want to read (Default 0 means unlimited)
 -fi | INPUT_FILE | File that i want to read
 -fo | OUTPUT_FILE | Log file where to store the results
