<p align="center">
  <img src="app/src/main/res/drawable/ic_app_icon_custom.png" width="128" height="128">
</p>

<h1 align="center">SecurePasswd MGMT</h1>

<p align="center">
  <a href="https://codeberg.org/fam007e/securepasswd_mgmt_apk/actions/workflows/android-build.yml"><img src="https://codeberg.org/fam007e/securepasswd_mgmt_apk/actions/workflows/android-build.yml/badge.svg" alt="Build Status"></a>
  <a href="https://codeberg.org/fam007e/securepasswd_mgmt_apk/actions/workflows/release.yml"><img src="https://codeberg.org/fam007e/securepasswd_mgmt_apk/actions/workflows/release.yml/badge.svg" alt="Release Status"></a>
</p>

A native port of the `SecurePasswd_MGMT` desktop application to Android using Jetpack Compose, Kotlin, and the C++ Android NDK.

## Features & Security Entropy
This Android application promises **identical security entropy** to its desktop CLI/GUI counterparts. By dynamically compiling the exact C `core` library via JNI, we bypass high-level platform RNG implementation differences:

* **Argon2id Key Derivation:** Enforces a 128MB memory cost with 3 iterations.
* **Salt Handling & PRNG:** Unique salt generation uses the kernel `getrandom(2)` syscall via a hardened shim, falling back to `/dev/urandom` with abort-on-failure; bounded draws use bias-free rejection sampling.
* **Memory Safety:** Sensitive data (passwords, TOTP seeds) is handled in `ByteArray` and explicitly zeroed immediately after use. Master passwords never exist as immutable strings in the JVM heap.
* **Zero-Knowledge Architecture:** No telemetry or tracking.
* **Advanced Navigation:** Real-time search, global alphabetical sorting, sticky headers, and an alphabet fast-scroller for efficient vault management.
* **Icon Masquerading:** Switch the launcher icon and name (Minimal black & white, Calculator, Notes, Files) so the vault is not advertised on your home screen.
* **Palettes & Tri-State Theme:** Nord / Dracula / Solarized palettes with a system → light → dark theme cycle and a themed splash screen.
* **Conflict-Aware Merging:** A Git-style "Merge Review" engine that detects and resolves duplicates/conflicts during imports or syncs, preventing data loss.
* **Two-Way Vault Sync:** Bidirectional LAN sync with the desktop app: a 512-bit one-time pairing secret (QR), ephemeral X25519 handshake with transcript-bound HKDF-SHA256 (forward secrecy + mutual authentication), ChaCha20-Poly1305 AEAD frames with replay protection, and a deterministic newer-wins merge with deletion tombstones — both devices converge identically.
* **OpenPGP Key Storage:** Armored public/secret GPG keys as vault records with a dedicated management screen, included in 2-way sync under the same merge rules.
* **Secure CSV Support:** Plaintext import and export with built-in protection against Formula Injection (CSV injection).
* **Password Health Checks:** Uses a privacy-preserving k-anonymity request to the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) API. Only the first 5 characters of a SHA-1 hash are sent. (Note: This is a monetary-free but proprietary network service, which F-Droid tags as `NonFreeNet`).
* **Modern Material UI:** Featuring intuitive desktop-like themes utilizing the Jetpack Compose framework.
* **Binary Transparency:** Supports bit-for-bit **reproducible builds**. Our build system is hardened with prefix-mapping and ELF stripping to ensure the distributed APK exactly matches the source code regardless of the local build path.

## Build Requirements
- Android Studio Iguana (or newer)
- Gradle 9.3+
- JDK 21
- Android NDK `25.1.8937393` and CMake `3.22.1`

## Building from source
```bash
git clone https://codeberg.org/fam007e/securepasswd_mgmt_apk.git
cd securepasswd_mgmt_apk
./gradlew assembleRelease
```

### Reproducible Builds
To verify that the build is bit-for-bit identical across environments:
1. Ensure you are using **JDK 21**.
2. Set the deterministic timestamp: `export SOURCE_DATE_EPOCH=1711075200`.
3. Build the release APK: `./gradlew assembleRelease`.
4. Compare the SHA-256 hash of the resulting APK with the official release.

## Contact & Support
For general inquiries or support, you can reach the maintainer at [email](mailto:faisalmoshiur+securepasswdmgmtapk@gmail.com).

## Community Standards
Please see our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) to understand how to engage with the project. Security flaws should be referenced via [SECURITY.md](SECURITY.md).
