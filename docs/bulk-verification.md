# Check several model folders

Available in the source candidate; not yet in the published 0.1.2 downloads.

```
vraelis models verify-many ./models/vision ./models/language
vraelis models verify-many "C:\Models\Vision" "C:\Models\Language" --json
```

Each folder uses its own `modellock.json`. The command reads files without creating
or approving lockfiles, signing anything, uploading results or requiring an account.
Quote paths containing spaces. Checks run sequentially, in argument order, with a
limit of 256 folders per invocation. Every argument is checked, including repeated
paths; there is no automatic recursive discovery.

The exit code covers the entire batch:

| Exit | Meaning |
| --- | --- |
| 0 | Every folder was unchanged against its lockfile |
| 1 | At least one folder changed, and every folder could be checked |
| 2 | At least one folder could not be checked, or the command failed |

An unreadable, missing or corrupt folder does not hide the remaining results.
An interrupted process is not a completed batch. A changed folder remains visible
in the results even when another folder makes the aggregate exit code 2.

`--json` emits `schema: "vraelis.model-batch.v1"`, aggregate `verdict`, `summary`
counts, and ordered `results`, each containing the input `folder` and the full
single-folder `result`. Human output includes changed files, coverage gaps and
format findings. Filenames and other untrusted strings are escaped in terminal
output. Neither unchanged nor the format findings are a malware or safety verdict.

```
vraelis models verify-many ./models/vision ./models/language --json > batch.json
```

Write redirected output outside the checked folders so it is not accidentally
included in verification. Batch JSON can include local paths and diagnostic
details; keep it private. `vraelis report` intentionally refuses a complete batch.
To submit a chosen result, extract that item's `result` into its own JSON file,
review it with `report --dry-run`, and explicitly submit it under its model name.
A separate reporting step must not replace verification's exit status.
