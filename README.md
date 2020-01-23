set_ns_last_pid
==================

This tool provides the semantics of writing to `/proc/sys/kernel/ns_last_pid`.
This is useful in the context of checkpoint/restore when having to choose the
pid of the next spawned process.

The tool does the following when requested to set `ns_last_pid` to a specific
`pid`:

1) If the tool has the `CAP_SYS_ADMIN` capability necessary to write to 
`/proc/sys/kernel/ns_last_pid`, then it does so.
2) If the tool is running unprivileged, then it spawns (and kill) as many
processes as necessary to reach the desired value of ns_last_pid.

Notes on the process spawning hack
------------------------------------

1) Using this technique on a quad core, we are able to cycle through pids at a
rate of 100,000 pids/s.
2) In a typical container, the maximum pid is 32768. This means that we can
cycle through the entire pid space in 300ms, which is reasonable when using it
for restoring processes.
3) When going above the maximum pid, the value of the next pid wraps around,
and becomes 300, not 1. This is due to a legacy security protection where the
kernel assumes pids < 300 are reserved for admins. This would supposedly allow
an admin to login into a machine even when a non-privileged process has
exhausted all the pids.

Usage
-------

There are two way to use the tool:

### 1. Direct CLI

The tool can be invoked directly to set a specific `ns_last_pid` value with:

```
set_ns_last_pid PID
```

### 2. As a server

The tool can run as a server. It listens on a specified UNIX socket:

```
set_ns_last_pid /absolute/path/to/socket
```

A client can connect to the socket, and request to set the `ns_last_pid` value.
An example code is provided in `example_client.c` and is invoked as such:

```
example_client /absolute/path/to/socket PID
```

Using a client is beneficial as running the CLI uses through some pids and may
impede performance when restoring consecutive pids.

License
------

The code is licensed under the Apache 2.0 license.
