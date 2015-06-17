package alvin.encrypt.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class EncryptUtil {
    private String encryptName;

    public EncryptUtil(String encryptName) {
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
}
