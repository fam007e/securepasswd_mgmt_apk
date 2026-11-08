# fdroiddata MR description (paste into the new merge request)

Title: New App: com.securepasswd.mgmt

---

**Supersedes !34800** (source fork was deleted before review; that MR had no
reviewer feedback or CI runs, so this is a clean re-submission).

**App:** SecurePasswd MGMT — offline password & TOTP manager (MIT), Kotlin +
Jetpack Compose UI with a native C core (SQLCipher, Argon2id, OpenSSL).

**Submission highlights:**

- Metadata copied verbatim from the upstream repo (`metadata/com.securepasswd.mgmt.yml`)
- `AntiFeatures: NonFreeNet` declared: the *optional* breach check queries the
  proprietary Have I Been Pwned API via k-anonymity (only a 5-char SHA-1 prefix
  is ever sent); everything else is fully offline
- Dependencies: AndroidX / Compose / CameraX / ZXing from Google Maven &
  Maven Central; `FreeDroidWarn` via JitPack (on the trusted-repo list);
  argon2 / OpenSSL / SQLCipher compiled from vendored git submodules
- No trackers, ads, GMS, API keys, or runtime binary downloads;
  `allowBackup=false`, no cleartext traffic, vault excluded from backups
- Reproducible-builds / Verified Builds support:
  - release APKs signed with `apksigner` (CI: Forgejo Actions)
  - `vcsInfo.include=false`, pinned `SOURCE_DATE_EPOCH`, NDK path remapping
    (`-ffile-prefix-map`), `-Wl,--build-id=none`
  - `AllowedAPKSigningKeys` pins the developer signing cert
  - `Binaries:` points at the Codeberg release APKs built by CI
  - CI builds every release **twice** in a clean workspace and refuses to
    publish on checksum mismatch; `SHA256SUMS` is published with each release
  - Gradle dependency verification (871 artifacts pinned, strict mode in CI)
    and a pinned Gradle wrapper checksum
- Fastlane metadata (title, short/full description, changelogs) lives in the
  upstream repo; screenshots are being added

**Versions:** first build entry is 2026.05.30 / 2026053001; AutoUpdateMode:
Version with UpdateCheckMode: Tags.
