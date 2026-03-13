# Contributing to SecurePasswd_MGMT_APK

Thank you for your interest! We welcome pull requests.

## Development Workflow
1. Fork the repository on Codeberg.
2. Clone your fork locally.
3. Make sure to have Android NDK installed (`./gradlew` will usually download it automatically depending on your system config).
4. Run all tests locally before submitting: `./gradlew test` and `./gradlew assembleDebug`.
5. Submit a Pull Request.

## Architecture
- `app/src/main/cpp`: Contains the C/C++ core logic. Changes here should generally reflect upstream changes in the desktop client's `/core` directory.
- `app/src/main/java/.../ui`: Contains all Jetpack Compose screens.

Please adhere to standard Kotlin `official` style guidelines and standard C `clang-format` conventions.
