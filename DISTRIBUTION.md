# Distribution and Publishing Guide

This guide outlines how to move from development builds to official production releases.

## 1. Production APK Signing
The current `release.yml` workflow builds an **unsigned** APK. Android devices require APKs to be signed by a private key to be installable.

### Steps to Sign:
1. **Generate a Keystore**: Use `keytool` (provided with the JDK) to create a `.jks` file.
   ```bash
   keytool -genkey -v -keystore securepasswd.jks -keyalg RSA -keysize 2048 -validity 10000 -alias securepasswd-mgmt-key
   ```

**Parameter Breakdown:**
- `-genkey`: Tells the tool to generate a new key pair (public/private).
- `-v`: **Verbose**. Shows detailed output during the process.
- `-keystore securepasswd.jks`: The filename of your "vault" file. You can change `securepasswd` to whatever you like.
- `-keyalg RSA`: The encryption algorithm. RSA is the standard for Android.
- `-keysize 2048`: The strength of the key. 2048 bits is highly secure and standard.
- `-validity 10000`: Lifetime of the key in days (approx. 27 years). Android requires keys to be valid for at least 25 years to ensure updates work throughout the app's lifespan.
- `-alias securepasswd-mgmt-key`: **Unique name inside the keystore.** This must match exactly in your CI configuration.

2. **Add to Codeberg Secrets**:
   Go to **Settings > Actions > Secrets** in your Codeberg repository and add the following four secrets:

   - `SIGNING_KEY_BASE64`: The content of your `.jks` file encoded in base64. Generate it with this command:
     ```bash
     base64 -w 0 securepasswd.jks
     ```
   - `KEYSTORE_PASSWORD`: The password you created for the keystore.
   - `KEY_ALIAS`: `securepasswd-mgmt-key`
   - `KEY_PASSWORD`: The password for the key (usually same as keystore password).

> [!CAUTION]
> **Keep your `.jks` file safe!** Do not commit it to your repository. Keep many backups of it in secure locations. If you lose this file, you will never be able to update your app on F-Droid or other stores again.

### Can I use PGP?
**For Android Installation: No.** 
The Android OS explicitly requires a signature based on X.509 certificates (V2/V3 signing scheme). PGP (Pretty Good Privacy) is a different standard and is not supported by the Android `PackageManager` for verifying app identity.

**For Release Verification: Yes.**
You *should* use PGP to sign the `SHA256SUMS` file of your APKs on Codeberg. This allows users to verify that the APK they downloaded from your repository is exactly the one you built, preventing man-in-the-middle attacks.

### F-Droid Signing
If you publish to the main **F-Droid** repository, **you don't need to provide a private signing key.** F-Droid builds the app from your source code and signs it with their own official F-Droid certificate. This is why F-Droid apps are trusted—they guarantee the binary matches the source code they audited.

## 2. Publishing to F-Droid
F-Droid is the primary app store for Free and Open Source software on Android.

### Requirements:
- **Fully Open Source**: No proprietary or "black box" libraries. Your app is clean.
- **Build from Source**: F-Droid builds apps on their own servers.
- **Metadata**: You must provide an [F-Droid metadata file](https://f-droid.org/en/docs/Build_Metadata_Reference/).

### Submission Process:
1. **Open a Request**: Open an issue on the [F-Droid Data GitLab](https://gitlab.com/fdroid/fdroiddata/-/issues) using the "New App" template.
2. **Provide Details**: They will ask for your repo URL and the build command (which is `./gradlew assembleRelease`).
3. **Validation**: Their automated tools will check your repo for tracking/proprietary code.
4. **Lifecycle**: Every time you push a new tag (e.g., `v1.0.1`), F-Droid will notice and automatically build/publish the update (usually within a few days).

### 3. Verifying F-Droid Builds
Because this project supports **bit-for-bit reproducible builds**, you can verify that the APK provided by F-Droid was built exactly from our source code. 

Our build system is hardened for total determinism:
- **NDK Pinning**: We use NDK `25.1.8937393` to ensure uniform toolchain behavior.
- **Path Stripping**: All absolute workspace and NDK paths are stripped from the final binary using `-f*-prefix-map` compiler flags.
- **Assembly Determinism**: Cryptographic assembly is compiled with `no-asm` where necessary to prevent non-deterministic instruction generation.

### Verification Steps:
1. Note the version and commit hash from F-Droid.
2. Clone the repository and checkout that commit.
3. Run the two-build local verification command:
   ```bash
   export SOURCE_DATE_EPOCH=1711075200

   # Build 1
   ./gradlew clean --no-daemon
   rm -rf app/build .gradle/configuration-cache
   ./gradlew :app:assembleRelease -PenableSplits -Ptarget.abis=arm64-v8a,armeabi-v7a --dependency-verification strict --no-daemon
   mkdir -p /tmp/build1 && cp app/build/outputs/apk/release/*.apk /tmp/build1/
   (cd /tmp/build1 && sha256sum *.apk > /tmp/build1.sha256)

   # Build 2
   ./gradlew clean --no-daemon
   rm -rf app/build .gradle/configuration-cache
   ./gradlew :app:assembleRelease -PenableSplits -Ptarget.abis=arm64-v8a,armeabi-v7a --dependency-verification strict --no-daemon
   mkdir -p /tmp/build2 && cp app/build/outputs/apk/release/*.apk /tmp/build2/
   (cd /tmp/build2 && sha256sum *.apk > /tmp/build2.sha256)

   # Compare
   diff -u /tmp/build1.sha256 /tmp/build2.sha256
   ```
4. Check that both builds produce byte-identical unsigned APKs.
5. Compare the unsigned APK checksum against F-Droid's build server output.

> [!TIP]
> Since your app uses the NDK, F-Droid will need to have the matching NDK version installed on their build servers. Our `build.gradle.kts` and `metadata/com.securepasswd.mgmt.yml` specify the exact version required.

## F-Droid Submission Checklist (verified against f-droid.org docs)

Done in this repo:
- [x] `metadata/com.securepasswd.mgmt.yml` (fdroiddata format) with `RepoType: git`,
      `Repo:`, `Binaries:`, `Builds` block (`versionName`, `versionCode`, `commit`,
      `subdir: app`, `gradle: yes`, `ndk: 25.1.8937393`, `gradleprops`, `output`),
      `AllowedAPKSigningKeys`, `AutoUpdateMode: Version`, `UpdateCheckMode: Tags`
- [x] `AntiFeatures: NonFreeNet` declared (Have I Been Pwned API) — undisclosed
      anti-features cause rejection; declared ones do not disqualify
- [x] MIT license, 100% FOSS deps (AndroidX, Compose, CameraX, ZXing, FreeDroidWarn
      via JitPack — JitPack.io is on F-Droid's trusted-repo list; vendored argon2,
      OpenSSL, SQLCipher are built from source submodules)
- [x] Fastlane metadata in-repo: `fastlane/metadata/android/en-US/` with
      `title.txt`, `short_description.txt` (<80 chars), `full_description.txt`,
      `images/icon.png`, `changelogs/<versionCode>.txt` (<500 chars)
- [x] No tracking/ads/GMS, unique applicationId, no executable downloads at runtime,
      no API keys, active development (>3 months), vault never backed up

TODO before opening the fdroiddata MR:
- [ ] Tag `v2026.05.30`, then replace `commit: v2026.05.30` in
      `metadata/com.securepasswd.mgmt.yml` with the exact 40-char commit hash
- [ ] Replace the upscaled 192px `icon.png` with a real 512x512 export of the
      SVG source
- [ ] Add 1–8 phone screenshots (PNG) to
      `fastlane/metadata/android/en-US/images/phoneScreenshots/`
- [ ] Verify the vendored OpenSSL submodule is 3.x (Apache-2.0); OpenSSL 1.x
      has the old advertising clause
- [ ] Confirm `gradle: yes` resolves to Gradle 9.3.1 on the buildserver — if
      fdroidserver's own Gradle is older, pin `gradle: 9.3.1` in the metadata
- [ ] Test with fdroidserver before the MR (Docker):
      `docker run -v $PWD:/repo registry.gitlab.com/fdroid/docker-executable:latest`
      then `fdroid lint`, `fdroid rewritemeta`, `fdroid checkupdates`, `fdroid build`
- [ ] Fork gitlab.com/fdroid/fdroiddata, add `metadata/com.securepasswd.mgmt.yml`,
      commit as "New App: com.securepasswd.mgmt", push, open MR;
      expect build+publish ~24-48h after merge

Reproducibility (Verified Builds): sign releases with `apksigner` (CI does),
publish the CI-built APKs via the `Binaries:` URL, keep `AllowedAPKSigningKeys`
pinned — F-Droid will then verify and publish the developer-signed APKs.
