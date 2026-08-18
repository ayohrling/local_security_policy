# AGENTS.md

This file provides guidance to AI coding assistants when working with code in this repository.

## Overview

Puppet module (`ayohrling-local_security_policy`) that manages Windows Local Security Policy (password policy, account lockout, audit policy, user rights assignment, security options) via the Windows `secedit` tool. Built with PDK; supports Puppet 6/7 on Windows only, but unit tests run on Linux.

## Commands

```sh
bundle install                    # install dependencies (PDK-managed Gemfile)
bundle exec rake parallel_spec    # run all unit tests (what CI runs)
bundle exec rspec spec/unit/puppet/provider/local_security_policy/policy_spec.rb          # single spec file
bundle exec rspec spec/unit/puppet/type/local_security_policy/local_security_policy_spec.rb -e 'some example'  # single example
bundle exec rake syntax lint metadata_lint check:symlinks check:git_ignore check:dot_underscore check:test_file rubocop  # CI syntax/lint job
```

Set `PUPPET_GEM_VERSION='~> 7'` (or `~> 6`) to pin the Puppet version, matching the CI matrix in `.github/workflows/pr.yml`.

Acceptance tests use beaker + Vagrant against Windows boxes (`spec/acceptance/`, nodesets in `spec/acceptance/nodesets/`), e.g. `BEAKER_set=win2022 bundle exec rspec spec/acceptance/suites/`. They require Vagrant with Windows VMs and are not run in CI.

## Architecture

The module is a single custom type/provider pair plus a supporting data-mapping class:

- `lib/puppet_x/lsp/security_policy.rb` — the heart of the module. `SecurityPolicy.lsp_mapping` is a large hash mapping every supported policy's GUI display name (e.g. `'Maximum password age'`) to its secedit key (`name:`), its INF section (`policy_type:` — one of `System Access`, `Event Audit`, `Privilege Rights`, `Registry Values`), and optionally `reg_type:` (registry value type as string) and `data_type:` (`:principal` for user/SID lists, `:quoted_string`). It also holds value-conversion logic: user names ↔ SIDs (sorted, `*`-prefixed), audit words ↔ numeric IDs, and registry values to `reg_type,value` form. **Adding support for a new policy setting usually means only adding an entry to `lsp_mapping`** (keep entries grouped by category and alphabetized within their section, matching the GUI name exactly).

- `lib/puppet/type/local_security_policy.rb` — the type. Resource title must exactly match a GUI name in `lsp_mapping` (validated via `SecurityPolicy.valid_lsp?`). `policy_type` and `policy_setting` are informational: they're always derived/overridden from the mapping in `defaultto`/`munge`, never trusted from the manifest. `policy_value` is validated per policy type and munged through `SecurityPolicy.convert_policy_value` so comparisons against system state are idempotent (e.g. SIDs are sorted before joining — see commit "Fix SID order idempotency").

- `lib/puppet/provider/local_security_policy/policy.rb` — the provider. `self.instances` runs `secedit /export`, parses the INF (encoded IBM437/UTF-16LE, converted to UTF-8) with the vendored inifile, and maps each key back to a display name via `find_mapping_from_policy_name` (unmapped system keys are silently skipped). Writes are batched: `self.prefetch` captures every `local_security_policy` resource in the catalog, and the first one to `flush` writes all of them into one INF applied with a single `secedit /configure`, so Windows validates the final combination rather than each intermediate state (interdependent settings like lockout duration/reset counter can only be satisfied together). Batching lives in `flush` rather than `self.post_resource_eval` deliberately: exceptions from `post_resource_eval` are only logged (`transaction.rb` teardown), whereas one raised in `flush` reaches the resource harness and marks the resource failed. `batchable?` is what keeps this safe — a policy is only written on another resource's behalf if Puppet is definitely going to change it this run (not noop, out of sync, no `schedule`/`require`/`subscribe`, not filtered out by `--tags`); everything else waits for its own `flush`. If the batched call is rejected, only the triggering policy is retried on its own and the rest are written individually as they flush. `self.post_resource_eval` now only clears per-run state, which matters because a puppet agent daemon reuses the process. `destroy` is intentionally a no-op — LSP settings can't be safely removed.

- `lib/puppet_x/twp/inifile.rb` — vendored INI parser/writer used for secedit INF files. Don't rewrite it; it handles secedit's quirks.

- `manifests/init.pp` — thin Hiera wrapper: `local_security_policy::policies` hash creates `local_security_policy` resources.

Both the type and provider carry a `LoadError` rescue block for loading `puppet_x` code across pluginsync layouts — preserve it when editing requires.

## Testing notes

- Unit specs stub all Windows interaction: `secedit` calls, `Puppet::Util::Windows::SID` lookups, and file I/O are mocked, with sample exported INF data in `spec/fixtures/unit/puppet/provider/local_security_policy/` (`secedit.inf`, `short_secedit.inf`).
- `spec/spec_helper.rb` and most boilerplate are PDK-managed (`pdk-version` in `metadata.json`); avoid hand-editing PDK-templated files.
