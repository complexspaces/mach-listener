# mach-listener

This crate lets you listen asynchronously on a registered mach port server and send messages back and forth to these servers

All listening is async and doesn't require a dedicated worker thread or blocking any of your application's threads.
Instead it utilizes Grand Central Dispatch (GCD/libdispatch) to dispatch events from efficient thread management provided by the OS.

### Security

Data sent through these connections is guaranteed to be delivered securely; only one process can be bound to a specific service name
at once and all data sent through mac ports can only be received by the original service listener by default.

## License

This crate is licensed under the [MIT license](./LICENSE-MIT).