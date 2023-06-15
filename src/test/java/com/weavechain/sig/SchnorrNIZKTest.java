package com.weavechain.sig;

import com.weavechain.curve25519.Constants;
import com.weavechain.curve25519.EdwardsPoint;
import com.weavechain.curve25519.Scalar;
import com.google.common.truth.Truth;
import io.ipfs.multibase.Base58;
import org.testng.annotations.Test;

import java.math.BigInteger;

public class SchnorrNIZKTest {

    private byte[] generateKey() {
        byte[] b = new byte[32];
        SchnorrNIZK.random().nextBytes(b);
        return b;
    }

    @Test
    protected void testProofPass1() throws Exception {
        Scalar scalar = SchnorrNIZK.scalarFromBigInteger(BigInteger.valueOf(123));
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(scalar);

        Transcript transcript = SchnorrNIZK.prove(generateKey(), scalar, pt);

        EdwardsPoint pt2 = pt;
        Truth.assertThat(SchnorrNIZK.verify(pt2, transcript)).isTrue();
    }

    @Test
    protected void testProofPass2() throws Exception {
        Scalar scalar = SchnorrNIZK.scalarFromBigInteger(BigInteger.probablePrime(10, SchnorrNIZK.random()));
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(scalar);
        Transcript transcript = SchnorrNIZK.prove(generateKey(),scalar, pt);

        EdwardsPoint pt2 = pt;
        Truth.assertThat(SchnorrNIZK.verify(pt2, transcript)).isTrue();
    }

    @Test
    protected void testProofFail1() throws Exception {
        Scalar scalar = SchnorrNIZK.scalarFromBigInteger(BigInteger.valueOf(321));
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(scalar);
        Transcript transcript = SchnorrNIZK.prove(generateKey(), scalar.add(scalar), pt);

        EdwardsPoint pt2 = pt;
        Truth.assertThat(SchnorrNIZK.verify(pt2, transcript)).isFalse();
    }

    @Test
    protected void testProofFail2() throws Exception {
        Scalar scalar = SchnorrNIZK.scalarFromBigInteger(BigInteger.valueOf(321));
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(scalar);
        Transcript transcript = SchnorrNIZK.prove(generateKey(),scalar, pt);

        EdwardsPoint pt2 = pt.multiply(scalar);
        Truth.assertThat(SchnorrNIZK.verify(pt2, transcript)).isFalse();
    }

    @Test
    protected void testHashKnown() throws Exception {
        String text = "test1234567890";

        //challenger
        byte[] commitment = new byte[64];
        SchnorrNIZK.random().nextBytes(commitment);

        //data owner
        Scalar k = SchnorrNIZK.hashScalar(text, commitment);
        Transcript transcript = SchnorrNIZK.prove(k);

        byte[] hash = k.toByteArray();
        String serialization = Base58.encode(transcript.toBytes());

        //verification by challenger, assuming the hash is known or can be computed
        Transcript deserialized = Transcript.fromBase58(serialization);
        Scalar kv = Scalar.fromBits(hash);
        Truth.assertThat(SchnorrNIZK.verify(kv, deserialized)).isTrue();
    }
}
