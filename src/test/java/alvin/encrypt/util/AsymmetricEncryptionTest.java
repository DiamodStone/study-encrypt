package alvin.encrypt.util;

import org.junit.Test;

import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

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

        Path srcFile = Paths.get(AsymmetricEncryptionTest.class.getResource("/photo-1.jpg").getFile());

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

        Path srcFile = Paths.get(AsymmetricEncryptionTest.class.getResource("/photo-1.jpg").getFile());
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
}