# How can I locally view events recorded by kvisor?

kvisor offers a mode where it will print all events that will be send to the CAST.AI backend to STDOUT. To
enable it, set the `ebpf-events-stdio-exporter-enabled` option to `true` in the `extraArgs` of the `agent`.

Here a full example:
```yaml
agent:
  enabled: true
  extraArgs:
    log-level: debug
    ebpf-events-enabled: true
    ebpf-events-stdio-exporter-enabled: false
```

As a word of caution though, depending on your cluster, this might print a lot of events!
