# Changelog

All notable changes to this project are documented in this file.

## v0.4.2 2026-08-19

### Fixed
- `FileOneTimeKeysStorage` no longer synchronizes on the boxed `interactionCounter`
  ([#11](https://github.com/VirgilSecurity/virgil-ratchet-kotlin/issues/11)). Locking on an `Int`
  boxed it into a `java.lang.Integer`, so the monitor identity changed with the counter value and
  `startInteraction`/`stopInteraction` never excluded each other — concurrent callers could corrupt
  the one-time key list (`ConcurrentModificationException`) or lose counter increments. All state is
  now guarded by a dedicated monitor object, which also keeps the class working under
  [JEP-401](https://openjdk.org/jeps/401) value objects, where synchronizing on a boxed primitive
  throws.
- `retrieveKey`, `retrieveAllKeys` and `reset` in `FileOneTimeKeysStorage` read shared state without
  holding any lock; they are now guarded as well.

## v0.4.1 2026-06-02

### Changed
- Updated dependencies:
  - `com.virgilsecurity.crypto:ratchet` -> `0.19.1` (stable)

## v0.4.0 2026-05-12

### Changed
- Updated dependencies:
  - `com.virgilsecurity.crypto:ratchet` -> `0.19.0-rc.11`
  - `com.virgilsecurity.sdk:virgil-sdk` -> `7.5.0`

### Fixed
- Resolved a SIGABRT and a JNI serialization failure originating in `virgil-crypto-c`.

### Breaking
- Upstream `com.virgilsecurity.crypto:ratchet:0.19.x` dropped a boolean argument from the
  `RatchetSession` initiate/respond API; call sites were updated accordingly.

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
