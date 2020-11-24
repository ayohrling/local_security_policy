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
