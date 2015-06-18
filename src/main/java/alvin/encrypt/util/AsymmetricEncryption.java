package alvin.encrypt.util;

import java.io.InputStream;
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
        return sign(ByteUtil.stringToByteArray(privateKey), algorithm, in);
    }

    public boolean verifySign(String publicKey, String algorithm, InputStream in, byte[] sign) throws Exception {
        return verifySign(ByteUtil.stringToByteArray(publicKey), algorithm, in, sign);
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
        return sign(ByteUtil.stringToByteArray(privateKey), algorithm, data);
    }

    public boolean verifySign(String publicKey, String algorithm, byte[] data, byte[] sign) throws Exception {
        return verifySign(ByteUtil.stringToByteArray(publicKey), algorithm, data, sign);
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

        public byte[] getPrivateKey() {
            return privateKey;
        }

        public byte[] getPublicKey() {
            return publicKey;
        }

        public String getPrivateKeyAsString() {
            return ByteUtil.byteArrayToString(getPrivateKey());
        }

        public String getPublicKeyAsString() {
            return ByteUtil.byteArrayToString(getPublicKey());
        }
    }
}
