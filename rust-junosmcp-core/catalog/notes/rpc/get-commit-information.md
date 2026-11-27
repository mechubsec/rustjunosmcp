## Example

`{"device": "<router>", "rpc": "get-commit-information", "args": {"include-configuration-revision": true}}`

## Reply fields that matter

- `commit-history/sequence-number`, `date-time`, `user`, `client`, `log` (newest first).
- `commit-confirmed` marks a commit still awaiting confirmation; `pending-commit` is present while one is scheduled.
- `configuration-revision` only appears with `include-configuration-revision`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-commit.html
