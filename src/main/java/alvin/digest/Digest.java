package alvin.digest;

import alvin.util.ByteUtils;

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
        MessageDigest md5 = MessageDigest.getInstance(digestName);
        return ByteUtils.byteArrayToString(md5.digest(data));
    }

    public String toString(String passwd, String encoding)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return toString(passwd.getBytes(encoding));
    }

    public String toString(InputStream in) throws IOException, NoSuchAlgorithmException {
        final MessageDigest md5 = MessageDigest.getInstance(digestName);

        byte[] buffer = new byte[512];
        int len;
        while ((len = in.read(buffer)) > 0) {
            md5.update(buffer, 0, len);
        }
        return ByteUtils.byteArrayToString(md5.digest());
    }
}
