HONOR Key Attestation Test (Android app source)

Purpose:
- Generate one temporary P-256 EC key in Android Keystore with a random attestation challenge.
- Read the Android attestation extension locally.
- Display attestationSecurityLevel, keymasterSecurityLevel, deviceLocked and verifiedBootState when available.
- Delete the temporary Keystore alias at the end.

Important:
- This is NOT strictly read-only: it temporarily creates a Keystore entry, then deletes it.
- It does not request root, alter SELinux, modify boot/system partitions, access private key bytes, or use the network.
- No INTERNET permission is declared.
- OEMs may disable or limit key attestation. Missing extension / exceptions are not proof of TEE damage.
- StrongBox is optional; TrustedEnvironment is a valid hardware-backed result.
- Do not share full certificate chains. Share only the displayed fields and any sanitized error text.

Build:
1. Open this folder in Android Studio (recent version).
2. Let Gradle sync.
3. Build > Build APK(s).
4. Install the generated APK on the HONOR phone.
5. Tap "Run hardware attestation test".
6. Share the displayed text, not certificate material.

The app uses Android platform APIs only; no third-party libraries.
