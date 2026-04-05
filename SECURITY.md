# Security Policy

## Supported Versions
Currently, only the `main` branch is actively supported with security updates.

## Cryptographic Entropy & Parity
**SecurePasswd MGMT guarantees 1:1 cryptographic parity with its desktop counterpart.**
The Android port achieves this by natively compiling the C `core` library using the Android NDK.

Critical Security Implementations:
1. **Key Derivation (At Rest):** Uses Argon2id via native bindings, utilizing a strictly enforced memory cost of 128MB and 3 iterations. Brute-force resilience is optimized for modern mobile hardware.
2. **Memory Safety (ByteArray Refactor):** Secrets (passwords, TOTP seeds, recovery codes) never exist as immutable `String` objects in the JVM heap. All sensitive data is handled in `ByteArray` and explicitly zeroed out (`sodium_memzero` in C, `.fill(0)` in Kotlin) immediately after use.
3. **Random Generation (PRNG):** All salts and password generation utilize `/dev/urandom` mapped directly into the C runtime via a `libsodium` system wrapper shim.
4. **Database Security:** Data is secured using SQLCipher encryption. Sensitive data is not included in standard Android backups (`allowBackup="false"`).
5. **Data Integrity (Merge Engine):** To prevent accidental data loss or overwrites, all imports (CSV/Sync) are processed by a conflict-aware "Merge Engine". This identifies identical entries and prompts for user resolution on conflicts, ensuring that your local data is never silently replaced.
6. **CSV Safety:** Plaintext CSV exports include formula injection protection (prefixing risky characters like `=`, `+`, `-`, `@` with a single quote) to mitigate attacks targeting spreadsheet software.
7. **Platform Hardening:**
   - **FLAG_SECURE:** Prevents screenshots, screen recording, and exposure in recent task lists.
   - **Sensitive Clipboard:** Utilizes `EXTRA_IS_SENSITIVE` flags for Android 13+ and automatic clearing after 30 seconds.
   - **Network Privacy:** Cleartext traffic is disabled globally; HIBP checks use k-Anonymity (anonymized hash ranges).
   - **Deterministic Builds:** Bit-for-bit reproducibility ensures that any user can verify that the distributed binary is the exact output of the provided source code.

## Reporting a Vulnerability
If you discover a security vulnerability, please do NOT report it via public issues on Codeberg.
Instead, send a private email to [email](mailto:faisalmoshiur+securepasswdmgmtapk@gmail.com). We will triage it within 48 hours.
