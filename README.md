# SecurePasswd_MGMT_APK

A natively port of the `SecurePasswd_MGMT` desktop application to Android using Jetpack Compose, Kotlin, and the C++ Android NDK.

## Features & Security Entropy
This Android application promises **identical security entropy** to its desktop CLI/GUI counterparts. By dynamically compiling the exact C `core` library via JNI, we bypass high-level platform RNG implementation differences:

* **Argon2id Key Derivation:** Enforces a 128MB memory cost with 3 iterations.
* **Salt Handling:** Unique salt generation relies exclusively on underlying `/dev/urandom` Linux kernel polling via a `libsodium` shim layer.
* **Memory Safety:** Sensitive data (passwords, TOTP seeds) is handled in `ByteArray` and explicitly zeroed immediately after use. Master passwords never exist as immutable strings in the JVM heap.
* **Zero-Knowledge Architecture:** No telemetry, tracking, or unexpected network calls.
* **Modern Material UI:** Featuring intuitive desktop-like themes utilizing the Jetpack Compose framework.

## Build Requirements
- Android Studio Iguana (or newer)
- Gradle 8.2+
- Android NDK `25.1.8937393` and CMake `3.22.1`

## Building from source
```bash
git clone https://codeberg.org/fam007e/securepasswd_mgmt_apk.git
cd securepasswd_mgmt_apk
./gradlew assembleDebug
```

## Contact & Support
For general inquiries or support, you can reach the maintainer at [email](mailto:faisalmoshiur+securepasswdmgmtapk@gmail.com).

## Community Standards
Please see our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) to understand how to engage with the project. Security flaws should be referenced via [SECURITY.md](SECURITY.md).
