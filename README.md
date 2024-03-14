# TLS Client Library README

## Disclaimer: Legacy Project

**Please note:** This project was developed several years ago and is no longer maintained. It still serves its purpose, but has not been updated to reflect the latest security standards or software developments. Users should exercise caution and evaluate the library's suitability for their current needs.

## Overview

The TLS Client Library provides an advanced interface for constructing HTTP clients that emulate the behavior of Go's `net/http` client, with the pivotal addition of specifying TLS (Transport Layer Security) client fingerprints. This enhancement is particularly useful for developers seeking to bypass or negotiate the increasingly common security measure of TLS Fingerprinting employed by servers to identify client browsers. 

TLS Fingerprinting is a sophisticated technique used by servers to deduce the type of client making a request, not just through the user-agent string, but by analyzing the unique characteristics of the client's TLS handshake. This method offers a more granular level of client identification, making simplistic user-agent spoofing insufficient for masking a client's identity. For a detailed understanding of TLS Fingerprinting and its implications, refer to the informative article by Fingerprint at [What is TLS Fingerprinting?](https://fingerprint.com/blog/what-is-tls-fingerprinting-transport-layer-security/).

Moreover, the mechanism of TLS Fingerprinting, particularly within the NodeJS ecosystem, is elaborately discussed in an article available at [TLS Fingerprinting with NodeJS](https://httptoolkit.tech/blog/tls-fingerprinting-node-js/#how-does-tls-fingerprinting-work), providing a comprehensive insight into its functionality and significance.


### Python Support

Thanks to [yeet-robotics/tls-client-lib](https://github.com/yeet-robotics/tls-client-lib), this library is also accessible for Python developers, allowing a wider range of application and implementation possibilities.

## Usage

The TLS Client Library enables the explicit definition of the client (Browser and Version) for server requests, granting developers the capability to fine-tune their HTTP client's identity. This feature is instrumental for applications requiring specific client identification to interact with web services that scrutinize TLS fingerprints.
