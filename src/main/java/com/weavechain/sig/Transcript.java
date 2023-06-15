
package com.weavechain.sig;

import com.weavechain.curve25519.*;
import io.ipfs.multibase.Base58;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Getter
@AllArgsConstructor
public class Transcript {

    private final EdwardsPoint u;

    private final Scalar c;

    private final Scalar z;

    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        outputStream.write(u.compress().toByteArray());
        outputStream.write(c.toByteArray());
        outputStream.write(z.toByteArray());

        return outputStream.toByteArray();
    }

    public String toBase58() throws IOException {
        return Base58.encode(toBytes());
    }

    public static Transcript fromBytes(byte[] input) throws InvalidEncodingException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(input);

        byte[] bu = new byte[32];
        byte[] bc = new byte[32];
        byte[] bz = new byte[32];

        if (inputStream.read(bu, 0, bu.length) <= 0) {
            return null;
        }
        if (inputStream.read(bc, 0, bc.length) <= 0) {
            return null;
        }
        if (inputStream.read(bz, 0, bz.length) <= 0) {
            return null;
        }

        return new Transcript(
                new CompressedEdwardsY(bu).decompress(),
                Scalar.fromBits(bc),
                Scalar.fromBits(bz)
        );
    }

    public static Transcript fromBase58(String input) throws InvalidEncodingException {
        return fromBytes(Base58.decode(input));
    }
}