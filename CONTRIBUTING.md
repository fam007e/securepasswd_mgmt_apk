# Contributing to SecurePasswd MGMT

Thank you for your interest! We welcome pull requests.

## Development Workflow
1. Fork the repository on Codeberg.
2. Clone your fork locally.
3. Make sure to have Android NDK installed (`./gradlew` will usually download it automatically depending on your system config).
4. Run all tests locally before submitting: `./gradlew test` and `./gradlew assembleDebug`.
5. Submit a Pull Request.

## Architecture
- `core/`: Contains the C/C++ business logic (cryptography, database, and sync). This core is shared with the `SecurePasswd_MGMT` desktop version. Changes here must maintain functional parity (Identity logic, Search, Argon2id parameters) across all platforms.
- `app/src/main/cpp`: Contains the JNI bridge (`core_jni.cpp`) and Android-specific build configuration.
- `app/src/main/java/.../ui`: Contains all Jetpack Compose screens.

Please adhere to standard Kotlin `official` style guidelines and standard C `clang-format` conventions.
