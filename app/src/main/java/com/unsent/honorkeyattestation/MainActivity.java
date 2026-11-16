package com.unsent.honorkeyattestation;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.graphics.Typeface;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

public class MainActivity extends Activity {
    private static final String ALIAS = "honor_temporary_attestation_test";
    private TextView output;
    private Button runButton;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 24, 24, 24);

        TextView intro = new TextView(this);
        intro.setText("HONOR Key Attestation Test\n\nCreates one temporary EC key in Android Keystore, requests an attestation certificate, reads selected security fields locally, then deletes the temporary key.\n\nNo root, network, private-key export, or system-partition changes. Key creation is a temporary Keystore write, so this is not strictly read-only.");
        intro.setTextSize(16);
        layout.addView(intro);

        runButton = new Button(this);
        runButton.setText("Run hardware attestation test");
        layout.addView(runButton);

        output = new TextView(this);
        output.setTextIsSelectable(true);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(13);
        output.setPadding(0, 20, 0, 0);
        layout.addView(output);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);

        runButton.setOnClickListener(v -> runTest());
    }

    private void runTest() {
        runButton.setEnabled(false);
        output.setText("Running…\n");
        new Thread(() -> {
            String result = Attestation.run(ALIAS);
            runOnUiThread(() -> {
                output.setText(result);
                runButton.setEnabled(true);
            });
        }).start();
    }

    static final class Attestation {
        static String run(String alias) {
            StringBuilder out = new StringBuilder();
            KeyStore ks = null;
            boolean created = false;
            try {
                ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);

                // Remove only a leftover entry created by this app's fixed alias.
                if (ks.containsAlias(alias)) ks.deleteEntry(alias);

                byte[] challenge = new byte[32];
                new SecureRandom().nextBytes(challenge);

                KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build();

                generator.initialize(spec);
                generator.generateKeyPair();
                created = true;

                java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
                    out.append("Attestation certificate chain: NOT AVAILABLE\n");
                    out.append("The device/provider did not return an X.509 attestation chain.\n");
                } else {
                    X509Certificate leaf = (X509Certificate) chain[0];
                    byte[] ext = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
                    out.append("Certificate chain length: ").append(chain.length).append('\n');
                    if (ext == null) {
                        out.append("Android attestation extension: NOT PRESENT\n");
                    } else {
                        Node outer = Der.parse(ext);
                        Node att = outer.firstChild();
                        if (att == null || att.tagNumber != 16) {
                            out.append("Attestation extension: present, format not recognized\n");
                        } else {
                            List<Node> f = att.children();
                            out.append("Attestation extension: present\n");
                            if (f.size() >= 8) {
                                out.append("attestationVersion: ").append(f.get(0).integer()).append('\n');
                                out.append("attestationSecurityLevel: ").append(level(f.get(1).integer())).append('\n');
                                out.append("keymasterVersion: ").append(f.get(2).integer()).append('\n');
                                out.append("keymasterSecurityLevel: ").append(level(f.get(3).integer())).append('\n');
                                Node root = findTag(f.get(7), 704);
                                if (root == null) root = findTag(f.get(6), 704);
                                if (root != null) {
                                    Node seq = root.firstChild();
                                    if (seq != null && seq.tagNumber == 16) {
                                        List<Node> r = seq.children();
                                        if (r.size() >= 3) {
                                            out.append("deviceLocked: ").append(r.get(1).bool()).append('\n');
                                            out.append("verifiedBootState: ").append(bootState(r.get(2).integer())).append('\n');
                                        } else out.append("RootOfTrust: present, fields incomplete\n");
                                    } else out.append("RootOfTrust: present, format not recognized\n");
                                } else {
                                    out.append("RootOfTrust: NOT FOUND in softwareEnforced/hardwareEnforced\n");
                                }
                            } else out.append("Attestation extension fields incomplete\n");
                        }
                    }
                }
            } catch (Throwable e) {
                out.append("TEST ERROR: ").append(e.getClass().getSimpleName());
                if (e.getMessage() != null) out.append(": ").append(e.getMessage());
                out.append('\n');
                out.append("This can indicate unsupported attestation, provider limitations, or an API error; it does not alone prove TEE damage.\n");
            } finally {
                if (ks != null) {
                    try {
                        if (ks.containsAlias(alias)) ks.deleteEntry(alias);
                        out.append("\nTemporary Keystore entry cleanup: ")
                           .append(ks.containsAlias(alias) ? "CHECK FAILED" : "deleted / absent").append('\n');
                    } catch (Exception e) {
                        out.append("\nTemporary Keystore cleanup: ERROR - ")
                           .append(e.getClass().getSimpleName()).append('\n');
                    }
                }
            }
            out.append("\nPrivacy: no network access; no private key or full certificate is displayed.\n");
            out.append("Interpretation: this tests Android hardware-backed key attestation, not every TEE function or firmware component.\n");
            return out.toString();
        }

        static String level(long n) {
            if (n == 0) return "Software (0)";
            if (n == 1) return "TrustedEnvironment (1)";
            if (n == 2) return "StrongBox (2)";
            return "Unknown (" + n + ")";
        }
        static String bootState(long n) {
            if (n == 0) return "Verified / green (0)";
            if (n == 1) return "SelfSigned (1)";
            if (n == 2) return "Unverified (2)";
            if (n == 3) return "Failed (3)";
            return "Unknown (" + n + ")";
        }
        static Node findTag(Node n, int tag) {
            if (n == null) return null;
            if (n.tagClass == 2 && n.tagNumber == tag) return n;
            for (Node c : n.children()) {
                Node hit = findTag(c, tag);
                if (hit != null) return hit;
            }
            return null;
        }
    }

    static final class Node {
        int tagClass, tagNumber;
        boolean constructed;
        byte[] data;
        List<Node> kids;
        Node firstChild() { List<Node> c = children(); return c.isEmpty() ? null : c.get(0); }
        List<Node> children() {
            if (kids != null) return kids;
            kids = new java.util.ArrayList<>();
            if (constructed) {
                int p = 0;
                while (p < data.length) {
                    Parse x = Der.read(data, p);
                    if (x == null || x.next <= p) break;
                    kids.add(x.node); p = x.next;
                }
            }
            return kids;
        }
        long integer() {
            if (data == null || data.length == 0) return -1;
            return new BigInteger(data).longValue();
        }
        boolean bool() { return data != null && data.length > 0 && data[0] != 0; }
    }

    static final class Parse {
        Node node; int next;
        Parse(Node n, int p) { node = n; next = p; }
    }

    static final class Der {
        static Node parse(byte[] b) {
            Parse p = read(b, 0);
            if (p == null || p.next != b.length) throw new IllegalArgumentException("Invalid DER");
            return p.node;
        }
        static Parse read(byte[] b, int p) {
            if (p >= b.length) return null;
            int first = b[p++] & 255;
            Node n = new Node();
            n.tagClass = (first >>> 6) & 3;
            n.constructed = (first & 32) != 0;
            int tn = first & 31;
            if (tn == 31) {
                tn = 0; int x;
                do {
                    if (p >= b.length) throw new IllegalArgumentException("Bad tag");
                    x = b[p++] & 255;
                    tn = (tn << 7) | (x & 127);
                } while ((x & 128) != 0);
            }
            if (p >= b.length) throw new IllegalArgumentException("Bad length");
            int len = b[p++] & 255;
            if ((len & 128) != 0) {
                int count = len & 127;
                if (count == 0 || count > 4 || p + count > b.length) throw new IllegalArgumentException("Bad length");
                len = 0;
                for (int i = 0; i < count; i++) len = (len << 8) | (b[p++] & 255);
            }
            if (len < 0 || p + len > b.length) throw new IllegalArgumentException("Truncated DER");
            n.tagNumber = tn;
            n.data = java.util.Arrays.copyOfRange(b, p, p + len);
            return new Parse(n, p + len);
        }
    }
}
