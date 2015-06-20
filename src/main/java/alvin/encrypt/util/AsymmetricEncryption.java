package alvin.encrypt.util;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymmetricEncryption {
    private String encryptName;

    public AsymmetricEncryption(String encryptName) {
        this.encryptName = encryptName;
    }

    public KeyPair makeKey(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptName);
        keyPairGenerator.initialize(keySize);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyPair result = new KeyPair();
        result.privateKey = keyPair.getPrivate().getEncoded();
        result.publicKey = keyPair.getPublic().getEncoded();
        result.keySize = keySize;
        return result;
    }

    public byte[] sign(byte[] privateKey, String algorithm, InputStream in) throws Exception {
        Signature signature = Signature.getInstance(algorithm + "with" + encryptName);
        signature.initSign(createPrivateKey(privateKey));
        byte[] buffer = new byte[1024];
        int count;
        while ((count = in.read(buffer)) > 0) {
            signature.update(buffer, 0, count);
        }
        return signature.sign();
    }

    public boolean verifySign(byte[] publicKey, String algorithm, InputStream in, byte[] sign) throws Exception {
        Signature signature = Signature.getInstance(algorithm + "with" + encryptName);
        signature.initVerify(createPublicKey(publicKey));
        byte[] buffer = new byte[1024];
        int count;
        while ((count = in.read(buffer)) > 0) {
            signature.update(buffer, 0, count);
        }
        return signature.verify(sign);
    }

    public byte[] sign(String privateKey, String algorithm, InputStream in) throws Exception {
        return sign(Hex.decodeHex(privateKey.toCharArray()), algorithm, in);
    }

    public boolean verifySign(String publicKey, String algorithm, InputStream in, byte[] sign) throws Exception {
        return verifySign(Hex.decodeHex(publicKey.toCharArray()), algorithm, in, sign);
    }

    public byte[] sign(byte[] privateKey, String algorithm, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(algorithm + "with" + encryptName);
        signature.initSign(createPrivateKey(privateKey));
        signature.update(data);
        return signature.sign();
    }

    public boolean verifySign(byte[] publicKey, String algorithm, byte[] data, byte[] sign) throws Exception {
        Signature signature = Signature.getInstance(algorithm + "with" + encryptName);
        signature.initVerify(createPublicKey(publicKey));
        signature.update(data);
        return signature.verify(sign);
    }

    public byte[] sign(String privateKey, String algorithm, byte[] data) throws Exception {
        return sign(Hex.decodeHex(privateKey.toCharArray()), algorithm, data);
    }

    public boolean verifySign(String publicKey, String algorithm, byte[] data, byte[] sign) throws Exception {
        return verifySign(Hex.decodeHex(publicKey.toCharArray()), algorithm, data, sign);
    }

    public byte[] encrypt(byte[] publicKey, int blockSize, byte[] srcData) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.ENCRYPT_MODE, createPublicKey(publicKey));
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (int i = 0; i < srcData.length; i += blockSize) {
                out.write(cipher.doFinal(srcData, i, Math.min(srcData.length - i, blockSize)));
            }
            return out.toByteArray();
        }
    }

    public byte[] encrypt(String publicKey, int blockSize, byte[] srcData) throws Exception {
        return encrypt(Hex.decodeHex(publicKey.toCharArray()), blockSize, srcData);
    }

    public byte[] decrypt(byte[] privateKey, int blockSize, byte[] encData) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.DECRYPT_MODE, createPrivateKey(privateKey));
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (int i = 0; i < encData.length; i += blockSize) {
                out.write(cipher.doFinal(encData, i, Math.min(encData.length - i, blockSize)));
            }
            return out.toByteArray();
        }
    }

    public byte[] decrypt(String privateKey, int blockSize, byte[] encData) throws Exception {
        return decrypt(Hex.decodeHex(privateKey.toCharArray()), blockSize, encData);
    }

    public long encrypt(byte[] publicKey, int blockSize, InputStream in, OutputStream out) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.ENCRYPT_MODE, createPublicKey(publicKey));
        int count;
        long total = 0;
        byte[] buffer = new byte[blockSize];
        while ((count = in.read(buffer)) > 0) {
            out.write(buffer, 0, count);
            total += count;
        }
        return total;
    }

    public long encrypt(String publicKey, int blockSize, InputStream in, OutputStream out) throws Exception {
        return encrypt(Hex.decodeHex(publicKey.toCharArray()), blockSize, in, out);
    }

    public long decrypt(byte[] privateKey, int blockSize, InputStream in, OutputStream out) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptName);
        cipher.init(Cipher.DECRYPT_MODE, createPrivateKey(privateKey));
        int count;
        long total = 0;
        byte[] buffer = new byte[blockSize];
        while ((count = in.read(buffer)) > 0) {
            out.write(buffer, 0, count);
            total += count;
        }
        return total;
    }

    public long decrypt(String privateKey, int blockSize, InputStream in, OutputStream out) throws Exception {
        return decrypt(Hex.decodeHex(privateKey.toCharArray()), blockSize, in, out);
    }

    private PublicKey createPublicKey(byte[] keyValue) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new X509EncodedKeySpec(keyValue);
        return KeyFactory.getInstance(encryptName).generatePublic(keySpec);
    }

    private PrivateKey createPrivateKey(byte[] keyValue) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PKCS8EncodedKeySpec(keyValue);
        return KeyFactory.getInstance(encryptName).generatePrivate(keySpec);
    }

    public static class KeyPair {
        private byte[] privateKey;
        private byte[] publicKey;
        private int keySize;

        public byte[] getPrivateKey() {
            return privateKey;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }

        public String getPrivateKeyAsString() {
            return Hex.encodeHexString(getPrivateKey());
        }

        public String getPublicKeyAsString() {
            return Hex.encodeHexString(getPublicKey());
        }

        public int getDecBlockSize() {
            return keySize / 8;
        }

        public int getEncBlockSize() {
            return getDecBlockSize() - 11;
        }

        public int getKeySize() {
            return keySize;
        }
    }
}
