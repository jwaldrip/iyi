# E3 BPF build-only check

The `PR147 E3 BPF build only` workflow is a build and synthetic-validator check. It does not load or attach BPF, acquire capabilities, launch the observer, start a container, or run strict proof. Its result is always `strict_eligible: false`.

The check requires the seven E3 witness files to match commit `be6d754aa7f7be709273281ff10fc0a0b68db8e6` byte for byte. It records that witness revision separately from the actual recipe checkout. A change to any witness file requires a new subject and review.

On the reviewed `ubuntu24 / 20261101.360.1` image, `proof/run_bpf_feasibility.sh --e3-build-only` uses the existing authenticated dependency staging and runner baselines. It compiles three native translation units with separate dependency files and assertions enabled, links the synthetic validator test and a separate observer link-check executable, builds the E3 BPF object, and validates their dependency and ELF/BTF records. The observer link-check executable is not run. The four staged libraries are linked from static archives; libc and the ELF interpreter remain dynamic.

The existing runner baseline invokes `setpriv --version` as a version-only tool probe. It does not invoke the privileged launcher. The pure-test executable and observer link-check executable receive separate native ELF validation; only the pure test is executed.

The retained evidence includes build logs and exit status, source and recipe revisions, source and artifact hashes, per-unit dependency files and header inventories, dependency lock and receipt digests, compiler identities, and the synthetic test log and exit status. Image drift fails the existing baseline rather than updating it automatically. No general environment or credentials are recorded.

The synthetic test constructs records in memory. Its success does not establish a successful kernel exec observation, object-byte custody, or source-callsite attribution. The earlier canary load/attach diagnostic exercised a different object and remains a separate non-strict result.

A later qualification needs an independently reviewed executable observer and supervisor path, protected descriptor custody, actual native exec versus read, timestamp-change and failed-exec controls, task and object correlation, complete descendant coverage and teardown accounting on the reviewed cage. The current supervisor remains unavailable for that qualification. Strict admission and independent-review holds remain in force.
