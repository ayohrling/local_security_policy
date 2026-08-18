## [2.2.0] - 2026-08-18
### Changed
- Apply every policy changed during a Puppet run with a single `secedit /configure` call instead of one call per resource. Interdependent policies (ex: `Account lockout duration` and `Reset account lockout counter after`) no longer fail depending on the order Puppet evaluates them in, and no ordering or `require` between the resources is needed. If the combined call is rejected, each policy is retried on its own so the failure is still reported against the resource that caused it. Policies that Puppet is not going to change -- already in sync, `noop`, excluded by `--tags`, or carrying a `schedule`, `require` or `subscribe` -- are never included in the combined call.

## [2.1.0] - 2026-07-22
### Added
- Add support for 'Domain controller: LDAP server signing requirements enforcement' and 'Network security: LDAP client encryption requirements'

## [2.0.0] - 2026-07-21
### Changed
- **BREAKING**: Replace Puppet 6/7 support with OpenVox 8; CI now runs on Ruby 3.2 and Ruby 4.0. The Gemfile now depends on the `openvox` gem (via `voxpupuli-test`) instead of `puppet`, and `PUPPET_VERSION` replaces `PUPPET_GEM_VERSION`
- **BREAKING**: Drop support for Windows 10, Windows Server 2012, and Windows Server 2012 R2

### Added
- Add support for Windows Server 2025

## [1.2.0] - 2026-07-16
- Add support for 'Domain controller' security options (Allow server operators to schedule tasks, Allow vulnerable Netlogon secure channel connections, LDAP server channel binding token requirements, LDAP server signing requirements, Refuse machine account password changes)

## [1.1.1] - 2023-01-03
- Fixed SID order idempotency - #124

## [1.1.0] - 2022-10-24
- Add Windows 2022 support and new policies - #125

## [1.0.0] - 2022-02-09
### Added
- Add Puppet7 Support - #115

### Changed
- Fix idempotency of local groups and users in Privilege Rights settings - #113
- Moved travis-ci tests to GitHub Actions - #119

## [0.8.1] - 2020-11-24
### Changed
- Fixed 'SDDL values are not idempotent' - #108

## [0.8.0] - 2020-11-10
### Added
- Newly introduced settings for Windows 2016 and 2019

## [0.7.2] - 2020-09-11
### Added
- Support for local or domain group lookup
- Support for policy specification via hiera

## [0.7.1] - 2020-07-08
### Changed
- invalid metadata tags removed

## [0.7.0] - 2020-07-08
### Added
- PDK support
- Acceptance tests
- Registry value validation

### Changed
- Fixed issues with intermittent failure of quoted values
- Resolved 'validate method error'
- Resolved munging error on domain controllers

## [0.6.3] - naeem98
 * Added 'Accounts: Administrator account status' setting for CIS 2.3.1.1

## [0.6.2]
 * Bug fix for 'No auditing' case issue - Jordan Wesolowski - #26
 * Fix issue where WMIC was timing out or crashing on systems joined to a domain - Thomas Linkin - #28

## [0.6.1]
 * Updates for typos in settings and official policy names - Gerben Welter - #19
 * Support old-style file-loading - Jordan Wesolowski - #24

## [0.6.0] - Adam Yohrling
 * Added new Network security settings, Typo Fixes, Idempotency - #18

## [0.5.2] - Ryan Russell-Yates
 * Updated all ruby files to UTF-8 forced encoding.

## [0.4.1] - Adam Yohrling
 * Fixed Issue 3 - undefined method error for 'Network access: Let Everyone permissions apply to
   anonymous users' setting

## [0.4.0] - Adam Yohrling
 * Added support for ensuring Privilege Rights settings as absent

## [0.3.2] - Adam Yohrling
 * Added support for currently unset values
 * Removed duplicate and invalid 'initalize' method
 * Cleaned out .DS_Store files that were in the repository
 * Moved references for external methods to self.class in flush method and removed duplicate data
