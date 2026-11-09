# Model checks in CI

The `report` command is in development on this branch; it is not in the published 0.1.2 binaries. Install the wheel built from this revision to try it. Ordinary `models verify` stays offline.

```
vraelis models verify ./model --json > result.json
vraelis report --file result.json --name my-model
```

Verification exits 0 (unchanged), 1 (changed), or 2 (cannot verify). Reporting is a separate operation: 0 means accepted, 2 means not confirmed. A report cannot turn a failed verification into a pass. Do not join these commands into a shell step that loses the first exit code.

Create an account report token through the account's CI controls, then store it as the CI secret `VRAELIS_REPORT_TOKEN`. Do not put the token in command arguments, committed files or logs. This is an **account-level report writer**, not a token limited to one repository or model. Only expose it to trusted code. Do not execute untrusted pull-request code with this secret.

Uploads contain the supplied model name, verdict, and changed relative filenames with their change types. Filenames can contain sensitive information; review them before enabling reporting. Absolute paths, hashes, failure reasons, configurations and other result fields are omitted. Unsupported change shapes are rejected. This first version supports model verification results, not agent checks or lockfile comparisons.

Reports are client-reported assertions, not server comparisons. Submission consumes account report allowances and may trigger configured change alerts. Acceptance does not guarantee notification delivery; repeated changes can be deduplicated by the service.

The command uses one HTTPS request to `https://data.vraelis.com/api/prompto/report`, without redirects, automatic retries or ambient proxy settings. Input and payload are limited to 4 MiB, changes to 10,000, response to 64 KiB. Socket inactivity timeout is 15 seconds; the CLI waits at most 30 seconds for transport. After a timeout or connection failure the server may already have saved the report. Delivery is uncertain; do not assume a retry is duplicate-free.

See `examples/model-check.yml` for separate verification and optional reporting steps. Adapt the model directory and install an approved CLI wheel before using it. Neither examples nor mocked transport tests establish real-account acceptance; that remains a release gate.
