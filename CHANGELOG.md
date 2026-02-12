# Changelog

All notable changes to this project are documented in this file.

## v0.3.0 2026-02-12

### Changed
- Modernized build tooling:
  - Gradle wrapper updated to `8.7`
  - Android Gradle Plugin updated to `8.5.2`
  - Kotlin plugin updated to `1.9.24`
- Updated dependencies:
  - `com.virgilsecurity.sdk:virgil-sdk` -> `7.4.0`
  - `com.virgilsecurity.crypto:ratchet` -> `0.17.2`
- Migrated CI from Travis to GitHub Actions:
  - Added `.github/workflows/build-and-test.yml`
  - Added `.github/workflows/publish-release.yml`
  - Kept `.travis.yml` as deprecated/no-op
- Test configuration now reads encrypted/decrypted env with keys:
  - `APP_ID`
  - `APP_KEY`
  - `BASE_SERVICE_URL`

### Fixed
- Updated ratchet service endpoint from `/pfs/v2/keys` to `/pfs/v3/keys`.
- Migrated secure session creation flow to current ratchet API signatures.
- Standardized PFS/Ratchet key-id computation on `RatchetKeyIdCompat` (`SHA-512(raw public key)[0..7]`) and updated tests accordingly.

### Breaking
- Upstream `com.virgilsecurity.crypto:ratchet:0.17.x` removed group ratchet API.
- Removed group chat API from this SDK (group support had already been removed on the `develop` branch earlier; `v0.3.0` is the first release that reflects it):
  - `SecureGroupSession`
  - `SecureChat.startNewGroupSession(...)`
  - `SecureChat.startGroupSession(...)`
  - group session storage interfaces/implementations
- Removed group-related tests and group test utilities.
