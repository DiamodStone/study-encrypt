package alvin.encrypt.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

public class SymmetricEncryption {
    private String encryptName;

    public SymmetricEncryption(String encryptName) {
        this.encryptName = encryptName;
    }

    public byte[] makeKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(encryptName);
        if (keySize > 0) {
            generator.init(keySize);
        }
        return generator.generateKey().getEncoded();
    }

    public int maxKeySize() throws Exception {
        return Cipher.getMaxAllowedKeyLength(encryptName);
    }

    public String makeKeyAsString(int keySize) throws NoSuchAlgorithmException {
        return ByteUtil.byteArrayToString(makeKey(keySize));
    }

    public byte[] encrypt(byte[] key, byte[] srcData) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, encryptName);
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(srcData);
    }

    public byte[] encrypt(String key, byte[] data) throws Exception {
        return encrypt(ByteUtil.stringToByteArray(key), data);
    }

    public byte[] decrypt(byte[] key, byte[] encData) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, encryptName);
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encData);
    }

    public byte[] decrypt(String key, byte[] data) throws Exception {
        return decrypt(ByteUtil.stringToByteArray(key), data);
    }

    public long encrypt(byte[] key, InputStream in, OutputStream out) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, encryptName);
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        CipherOutputStream cout = new CipherOutputStream(out, cipher);

        long total = 0;
        int count;
        byte[] buffer = new byte[1024];
        while ((count = in.read(buffer)) > 0) {
            cout.write(buffer, 0, count);
            total += count;
        }
        try {
            buffer = cipher.doFinal();
            total += buffer.length;
            out.write(buffer);
        } catch (BadPaddingException | IllegalBlockSizeException ignore) {
        }
        cout.flush();
        return total;
    }

    public long encrypt(String key, InputStream in, OutputStream out) throws Exception {
        return encrypt(ByteUtil.stringToByteArray(key), in, out);
    }

    public long decrypt(byte[] key, InputStream in, OutputStream out) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, encryptName);
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        CipherInputStream cin = new CipherInputStream(in, cipher);

        long total = 0;
        int count;
        byte[] buffer = new byte[1024];
        while ((count = cin.read(buffer)) > 0) {
            out.write(buffer, 0, count);
            total += count;
        }
        return total;
    }

    public long decrypt(String key, InputStream in, OutputStream out) throws Exception {
        return decrypt(ByteUtil.stringToByteArray(key), in, out);
    }
}
