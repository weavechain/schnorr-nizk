package com.weavechain.sig;

import com.weavechain.curve25519.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class SchnorrNIZK {

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public static SecureRandom random() {
        return RANDOM.get();
    }

    public static Transcript prove(byte[] pk, Scalar x, EdwardsPoint pt) throws NoSuchAlgorithmException {
        Scalar r = Scalar.fromBits(pk);
        EdwardsPoint u = Constants.ED25519_BASEPOINT.multiply(r);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Constants.ED25519_BASEPOINT.compress().toByteArray());
        md.update(pt.compress().toByteArray());
        md.update(u.compress().toByteArray());
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);
        Scalar z = k.multiplyAndAdd(x, r);

        return new Transcript(u, k, z);
    }

    public static boolean verify(EdwardsPoint pt, Transcript transcript) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Constants.ED25519_BASEPOINT.compress().toByteArray());
        md.update(pt.compress().toByteArray());
        md.update(transcript.getU().compress().toByteArray());
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);

        return Arrays.equals(k.toByteArray(), transcript.getC().toByteArray())
                && Arrays.equals(
                    Constants.ED25519_BASEPOINT.multiply(transcript.getZ()).compress().toByteArray(),
                    pt.multiply(k).add(transcript.getU()).compress().toByteArray()
                );
    }

    public static Transcript prove(Scalar k) throws NoSuchAlgorithmException {
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(k);
        byte[] r = new byte[32];
        random().nextBytes(r);
        return SchnorrNIZK.prove(r, k, pt);
    }

    public static boolean verify(Scalar k, Transcript transcript) throws NoSuchAlgorithmException {
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(k);
        return verify(pt, transcript);
    }

    public static Scalar scalarFromBigInteger(BigInteger value) {
        byte[] data = value.toByteArray();
        byte[] dest = new byte[32];
        int start = Math.max(0, data.length - 32);
        for (int j = start; j < data.length; j++) {
            dest[j - start] = data[data.length - 1 + start - j];
        }
        return Scalar.fromBits(dest);
    }

    public static Scalar hashScalar(String text, byte[] challenge) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(text.getBytes(StandardCharsets.UTF_8));
        if (challenge != null) {
            md.update(challenge);
        }

        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }
}