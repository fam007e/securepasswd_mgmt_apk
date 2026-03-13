# SecurePasswd_MGMT_APK - Android Port Implementation Plan

This app is going to be a android version of this desktop application SecurePasswd_MGMT from https://github.com/fam007e/SecurePasswd_MGMT.

## 1. Architecture Overview
**UI Layer:** Native Android built with Kotlin and Jetpack Compose.
**Business Logic / Core:** The existing C `core` library (Argon2, SQLCipher, Libsodium, OpenSSL) compiled natively via the Android NDK and exposed to Kotlin through JNI (Java Native Interface).
**Tooling:** CMake and Gradle. Since the project already uses CMake, it hooks seamlessly into the Android build system.

## 2. JNI/NDK Integration
*   **CMake Configuration:** Extend the current `CMakeLists.txt` to dynamically detect Android platforms and link against NDK libraries (e.g., Android `log`).
*   **JNI Wrapper (C++):** A `core_jni.cpp` bridge wraps native C functions. For memory safety, all secrets are passed as `jbyteArray` instead of `jstring`, ensuring they can be zeroed in the native layer and never exist as immutable strings in the JVM.
*   **Cross-Compiled Dependencies:** Statically link `libsodium`, `argon2`, `sqlcipher`, and `openssl`. 

## 3. TOTP Addition (QR Code & Manual Entry)
*   **Camera integration:** Implement a scanning screen using the Android **CameraX APIs** alongside **Google ML Kit Barcode Scanning** for fast, local QR code processing.
*   **URI Parsing:** Parse the standard `otpauth://...` URI format contained in TOTP QR codes to extract the base32 secret, issuer name, and account identifier.
*   **Manual Input Fallback:** Provide a standard text field fallback form to allow users to manually type or paste their base32 TOTP secret if a camera scan fails.
*   **Core Storage Integration:** Parsed secrets remain in `ByteArray` throughout the Kotlin layer and are passed down the JNI bridge to be stored in the SQLCipher database. All buffers are zeroed (`fill(0)`) immediately after storage.

## 4. Secure Vault Synchronization
Syncing requires safely moving the SQLCipher database and its accompanying salt file (`vault.db` and `vault.db.salt`). Because the database is highly encrypted at rest via Argon2id, standard transport mechanisms are safe.

### Recommended Approach: Encrypted Archive & Android Intents (Phase 1)
1.  **Export:** Compress `vault.db` and `vault.db.salt` into a unified extension archive (e.g., `vault.spmgmt`).
2.  **Native Sharing:** Use Android's built-in `Intent.ACTION_SEND` so the user can send the archive to another device via **Nearby Share**, Bluetooth, or save it to a local/cloud drive.
3.  **Import Hooks:** Register the active Android app to handle `.spmgmt` files via deep-linking/file parsing. When opened, it extracts the DB/salt, overwrites the local state (after confirmation), and prompts for the master password to test decrypting it.

### Premium Approach: Local Wi-Fi Direct Sync (Phase 2)
1.  **Desktop/Host Mode:** Sender acts as an ephemeral HTTP server on the local LAN. It generates a single-use pairing QR code containing the host's LAN IP, port, and a one-time ECDH public key.
2.  **Receiver Mode:** The receiving phone app scans this QR code, performs a Diffie-Hellman key exchange, and connects securely.
3.  **Transfer:** The bundled `db` and `salt` payload is transmitted over the encrypted local socket. Both devices immediately terminate the connection post-transfer.

## 5. Phased Execution Strategy

### Phase 1: NDK Setup and Core Wrapper
*   Launch Android Studio project with C++ Support.
*   Integrate the existing `core/` directory and compile dependencies for Android ABIs.
*   Write and test the `core_jni.cpp` wrapper, utilizing Android JUnit tests to assert cryptographic parity with the desktop CLI/GUI.

### Phase 2: Android Jetpack UI & Core Flow
*   Build the main Material Design 3 UI: Login Screen, Password Vault List, entry details.
*   Connect JNI bridge to trigger password derivation, fetch logic, and built-in password generators.
*   Replicate desktop-style TOTP countdown circles/refresh progress bars.

### Phase 3: TOTP Camera Integrations
*   Add Android camera permissions.
*   Implement the CameraX/MLKit viewfinder screen.
*   Bridge QR data successfully into the add-entry workflow.

### Phase 4: Sync Implementations
*   Implement the archive packager for `db` + `salt`.
*   Implement Storage Access Framework (SAF) capabilities for simple exporting/importing to onboard device storage files.
*   (Optional) Design the WebSockets/HTTP server system for cross-platform LAN syncing.
