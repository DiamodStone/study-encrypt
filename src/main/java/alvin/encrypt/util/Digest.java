package alvin.encrypt.util;

import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Digest {

    private String digestName;

    public Digest(String digestName) {
        this.digestName = digestName;
    }

    public String toString(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(digestName);
        return Hex.encodeHexString(digest.digest(data));
    }

    public String toString(String passwd, String encoding)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return toString(passwd.getBytes(encoding));
    }

    public String toString(InputStream in) throws IOException, NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance(digestName);

        byte[] buffer = new byte[1024];
        int len;
        while ((len = in.read(buffer)) > 0) {
            digest.update(buffer, 0, len);
        }
        return Hex.encodeHexString(digest.digest());
    }
}
