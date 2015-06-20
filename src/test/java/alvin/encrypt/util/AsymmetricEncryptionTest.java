package alvin.encrypt.util;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class AsymmetricEncryptionTest {

    @Test
    public void test_sign_with_private_key() throws Exception {
        AsymmetricEncryption encrypt = new AsymmetricEncryption("RSA");
        AsymmetricEncryption.KeyPair keyPair = encrypt.makeKey(1024);

        String publicKey = keyPair.getPublicKeyAsString();
        String privateKey = keyPair.getPrivateKeyAsString();

        final byte[] srcData = "Hello World".getBytes("UTF-8");

        byte[] sign = encrypt.sign(privateKey, "SHA1", srcData);
        assertThat(encrypt.verifySign(publicKey, "SHA1", srcData, sign), is(true));

        byte[] srcData2 = srcData.clone();
        srcData2[1]++;
        assertThat(encrypt.verifySign(publicKey, "SHA1", srcData2, sign), is(false));

        sign[0]++;
        assertThat(encrypt.verifySign(publicKey, "SHA1", srcData, sign), is(false));
    }

    @Test
    public void test_sign_to_file() throws Exception {
        AsymmetricEncryption encrypt = new AsymmetricEncryption("RSA");
        AsymmetricEncryption.KeyPair keyPair = encrypt.makeKey(1024);

        String publicKey = keyPair.getPublicKeyAsString();
        String privateKey = keyPair.getPrivateKeyAsString();

        Path srcFile = Paths.get(AsymmetricEncryptionTest.class.getResource("/photo.jpg").getFile());

        byte[] sign;
        try (InputStream in = Files.newInputStream(srcFile, StandardOpenOption.READ)) {
            sign = encrypt.sign(privateKey, "MD5", in);
        }

        try (InputStream in = Files.newInputStream(srcFile, StandardOpenOption.READ)) {
            assertThat(encrypt.verifySign(publicKey, "MD5", in, sign), is(true));
        }
    }

    @Test
    public void test_bad_sign_to_file() throws Exception {
        AsymmetricEncryption encrypt = new AsymmetricEncryption("RSA");
        AsymmetricEncryption.KeyPair keyPair = encrypt.makeKey(1024);

        String publicKey = keyPair.getPublicKeyAsString();
        String privateKey = keyPair.getPrivateKeyAsString();

        Path srcFile = Paths.get(AsymmetricEncryptionTest.class.getResource("/photo.jpg").getFile());
        Path tempFile = Files.createTempFile("test", ".tmp");

        try {
            Files.copy(srcFile, tempFile, StandardCopyOption.REPLACE_EXISTING);

            byte[] sign;
            try (InputStream in = Files.newInputStream(tempFile, StandardOpenOption.READ)) {
                sign = encrypt.sign(privateKey, "MD5", in);
            }

            try (RandomAccessFile randomAccessFile = new RandomAccessFile(tempFile.toFile(), "rw")) {
                randomAccessFile.seek(1);
                randomAccessFile.writeByte(123);
            }

            try (InputStream in = Files.newInputStream(tempFile, StandardOpenOption.READ)) {
                assertThat(encrypt.verifySign(publicKey, "MD5", in, sign), is(false));
            }
        } finally {
            Files.delete(tempFile);
        }
    }

    @Test
    public void test_rsa_encrypt() throws Exception {
        final String srcString = "Hello World";
        final byte[] srcData = srcString.getBytes("UTF-8");

        AsymmetricEncryption encrypt = new AsymmetricEncryption("RSA");
        AsymmetricEncryption.KeyPair keyPair = encrypt.makeKey(1024);

        String publicKey = keyPair.getPublicKeyAsString();
        String privateKey = keyPair.getPrivateKeyAsString();
        int encBlockSize = keyPair.getEncBlockSize();
        int decBlockSize = keyPair.getDecBlockSize();

        byte[] encData = encrypt.encrypt(publicKey, encBlockSize, srcData);
        assertThat(srcString, not(new String(encData, "UTF-8")));

        byte[] decData = encrypt.decrypt(privateKey, decBlockSize, encData);
        assertThat(new String(decData, "UTF-8"), is(srcString));
    }

    @Test
    public void test_full() throws Exception {
        final Path srcFile = Paths.get(AsymmetricEncryptionTest.class.getResource("/photo.jpg").toURI());
        AsymmetricEncryption asymmetricEncryption = new AsymmetricEncryption("RSA");
        SymmetricEncryption symmetricEncryption = new SymmetricEncryption("AES");

        // A生成一对密钥，并与B共享公钥
        AsymmetricEncryption.KeyPair keyPairA = asymmetricEncryption.makeKey(2048);

        // B生成一对密钥，并与A共享公钥
        AsymmetricEncryption.KeyPair keyPairB = asymmetricEncryption.makeKey(2048);

        // A生成文件加密密钥
        byte[] fileKeyA = symmetricEncryption.makeKey(256);

        // A用B的公钥将文件密钥加密
        byte[] encFileKeyA = asymmetricEncryption.encrypt(keyPairB.getPublicKey(), keyPairB.getEncBlockSize(), fileKeyA);

        // A用自己的私钥对加密结果签名
        byte[] signA = asymmetricEncryption.sign(keyPairA.getPrivateKey(), "SHA1", encFileKeyA);

        // A将加密的文件密钥及签名发送给B
        String encFileKeyContent = Base64.encodeBase64String(encFileKeyA);
        String signContent = Base64.encodeBase64String(signA);

        // A使用文件密钥将数据加密, 发送给B
        String encFileContent;
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            try (InputStream in = Files.newInputStream(srcFile)) {
                symmetricEncryption.encrypt(fileKeyA, in, out);
            }
            encFileContent = Base64.encodeBase64String(out.toByteArray());
        }

        // ......

        // B接收到加密的文件密钥和签名，对利用A的公钥对文件密钥进行验签
        byte[] encFileKeyB = Base64.decodeBase64(encFileKeyContent);
        byte[] signB = Base64.decodeBase64(signContent);
        assertTrue(asymmetricEncryption.verifySign(keyPairA.getPublicKey(), "SHA1", encFileKeyB, signB));
        assertArrayEquals(encFileKeyB, encFileKeyA);

        // B利用自己的私钥对加密的文件密钥进行解密，得到文件密钥
        byte[] fileKeyB = asymmetricEncryption.decrypt(keyPairB.getPrivateKey(), keyPairB.getDecBlockSize(), encFileKeyB);
        assertArrayEquals(fileKeyB, fileKeyA);

        // B利用得到的文件密码对文件内容进行解密
        byte[] encFileData = Base64.decodeBase64(encFileContent);
        // showFileContent(encFileData);

        byte[] fileData = symmetricEncryption.decrypt(fileKeyB, encFileData);

        int index = 0;
        try (InputStream in = Files.newInputStream(srcFile)) {
            int b;
            while ((b = in.read()) >= 0) {
                assertThat((byte) b, is(fileData[index++]));
            }
        }

        showFileContent(fileData);
    }

    private void showFileContent(byte[] fileData) {
        JDialog jd = new JDialog();
        jd.setModal(true);

        Icon image = new ImageIcon(fileData);
        jd.add(BorderLayout.CENTER, new JLabel(image));

        jd.pack();
        jd.setLocationRelativeTo(null);
        jd.setVisible(true);
    }
}