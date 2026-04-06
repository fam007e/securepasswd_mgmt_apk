## Description
<!-- Describe your changes in detail here -->

## Related Issues
<!-- If this PR fixes an open issue, link to it using "Fixes #<ISSUE_NUMBER>" -->

## Implementation Details
<!-- How did you implement this? (e.g., "Added a new C function and JNI wrapper," or "Updated the Compose VaultScreen") -->

## Security Check
- [ ] This change maintains the 128MB Argon2id memory cost and 3 iterations
- [ ] This change follows the `ByteArray` refactor (no immutable `String` secrets)
- [ ] Sensitive data is explicitly zeroed after use (`sodium_memzero` or `.fill(0)`)
- [ ] No raw secrets or master passwords are logged to logcat
- [ ] I have read and followed the [SECURITY.md](SECURITY.md) guidelines

## Checklist
- [ ] I have performed a self-review of my own code
- [ ] I have verified that no absolute paths leak into the native binary via `strings` audit
- [ ] I have added tests that prove my fix is effective or that my feature works
