# message-server

Message server for **URmessage** — private messaging built on the URnetwork mesh.

The message server stores encrypted records, orders them, serves history, and prunes by retention
policy. It never decrypts anything, and it is not the authority on group membership: that lives in
the MLS (RFC 9420) group state held by clients.

## Status

Early development. The protocol design lives with the client work and is tracked in
`urnetwork-message-server`.

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
