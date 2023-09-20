# snisslbug

## What

Demonstrates a bug in Java's handling of SNI server names.

It appears that `SNIServerName` settings are persisted across individual client socket connections.

The first connection made from the client determines whether/which SNI server names are being
sent to the server, regardless of what server names are set later on via the socket-specific
`SSLParameters`

The only workaround I've found so far is to not reuse `SSLContext` for these configurations
from the client-side. Note that for the server-side, `SNIMatcher`s appear to not be reused
across calls, indicating not only an unintuitive but also an inconsistent behavior.

## Why

`SSLContext`s are supposed to be reusable, and great efforts were made to not erroneously reuse
settings, as can be seen by the many cloned/duplicated objects in the SSL code, e.g., in `SSLParameters`
and `SNIServerName`, for example.

This bug can lead to situations where client requests fail unexpectedly due to race conditions, etc.

## Where

It looks like any Java VM I tested was affected (versions 8-22 on macOS, Linux, Windows, IBM i, z/OS).

## How

Run the following commands to build the jar (Maven required):

    mvn package

Run the following commands to run the jar

    cd target
    java -jar snissl-1.0-SNAPSHOT.jar 

Observe the output:

    **** START DEMO (reuseSSLContext=true) ****
    
    Connecting to server; setServerName=snihostName
    Setting SNI Matchers: true
    Current server names: null
    Setting server names: [type=host_name (0), value=snihostName]
    Received SNI server name: type=host_name (0), value=snihostName
    
    Connecting to server; setServerName=anotherSnihostName
    Current server names: null
    Setting server names: [type=host_name (0), value=anotherSnihostName]
    Setting SNI Matchers: true
    Received SNI server name: type=host_name (0), value=snihostName
    
    Connecting to server; setServerName=null
    Setting SNI Matchers: true
    Current server names: null
    Not setting server names
    Received SNI server name: type=host_name (0), value=snihostName
    
    
    **** START DEMO (reuseSSLContext=false) ****
    
    Connecting to server; setServerName=snihostName
    Setting SNI Matchers: true
    Current server names: null
    Setting server names: [type=host_name (0), value=snihostName]
    Received SNI server name: type=host_name (0), value=snihostName
    
    Connecting to server; setServerName=anotherSnihostName
    Setting SNI Matchers: true
    Current server names: null
    Setting server names: [type=host_name (0), value=anotherSnihostName]
    Received SNI server name: type=host_name (0), value=anotherSnihostName
    
    Connecting to server; setServerName=null
    Setting SNI Matchers: true
    Current server names: null
    Not setting server names
    Did not receive SNI server name

See that in the second block of the first `DEMO` section (where `SSLContext` is reused),
the client sets the SNI hostname "anotherSnihostName", but "snihostName" is being received.
The same applies in the third block, where no SNI hostname is sent by the client.

Note that everything works as expected when `SSLContext` is not being reused (second `DEMO` section).

## Who

Copyright 2023 by Christian Kohlschütter

Licensed under the Apache License, Version 2.0
