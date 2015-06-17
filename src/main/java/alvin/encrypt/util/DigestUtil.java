package alvin.encrypt.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class DigestUtil {

    private String digestName;

    public DigestUtil(String digestName) {
        this.digestName = digestName;
    }

    public String toString(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(digestName);
        return ByteUtil.byteArrayToString(digest.digest(data));
    }

    public String toString(String passwd, String encoding)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return toString(passwd.getBytes(encoding));
    }

    public String toString(InputStream in) throws IOException, NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance(digestName);

        byte[] buffer = new byte[512];
        int len;
        while ((len = in.read(buffer)) > 0) {
            digest.update(buffer, 0, len);
        }
        return ByteUtil.byteArrayToString(digest.digest());
    }
}
