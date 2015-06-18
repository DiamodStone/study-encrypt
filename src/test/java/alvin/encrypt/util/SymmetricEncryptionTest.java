package alvin.encrypt.util;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

public class SymmetricEncryptionTest {

    @Test
    public void test_des_enc_and_dec() throws Exception {
        final String expectedString = "Hello Java";
        final byte[] expectedData = expectedString.getBytes("UTF-8");

        SymmetricEncryption encrypt = new SymmetricEncryption("DES");

        String key = encrypt.makeKeyAsString(56);
        byte[] encData = encrypt.encrypt(key, expectedData);

        assertThat(encData.length, greaterThan(expectedData.length));
        assertThat(new String(encData, "UTF-8"), not(expectedString));

        byte[] srcData = encrypt.decrypt(key, encData);
        assertThat(srcData.length, is(expectedData.length));
        assertThat(new String(srcData, "UTF-8"), is(expectedString));
    }

    @Test
    public void test_3des_enc_and_dec() throws Exception {
        final String expectedString = "Hello Java";
        final byte[] expectedData = expectedString.getBytes("UTF-8");

        SymmetricEncryption encrypt = new SymmetricEncryption("DESede");

        String key = encrypt.makeKeyAsString(168);
        byte[] encData = encrypt.encrypt(key, expectedData);

        assertThat(encData.length, greaterThan(expectedData.length));
        assertThat(new String(encData, "UTF-8"), not(expectedString));

        byte[] srcData = encrypt.decrypt(key, encData);
        assertThat(srcData.length, is(expectedData.length));
        assertThat(new String(srcData, "UTF-8"), is(expectedString));
    }

    @Test
    public void test_aes_enc_and_dec() throws Exception {
        final String expectedString = "Hello Java";
        final byte[] expectedData = expectedString.getBytes("UTF-8");

        SymmetricEncryption encrypt = new SymmetricEncryption("AES");

        String key = encrypt.makeKeyAsString(256);
        byte[] encData = encrypt.encrypt(key, expectedData);

        assertThat(encData.length, greaterThan(expectedData.length));
        assertThat(new String(encData, "UTF-8"), not(expectedString));

        byte[] srcData = encrypt.decrypt(key, encData);
        assertThat(srcData.length, is(expectedData.length));
        assertThat(new String(srcData, "UTF-8"), is(expectedString));
    }

    @Test
    public void test_aes_enc_and_dec_by_stream() throws Exception {
        SymmetricEncryption encrypt = new SymmetricEncryption("AES");
        String key = encrypt.makeKeyAsString(256);

        Path srcFile = Paths.get(SymmetricEncryptionTest.class.getResource("/photo-1.jpg").getFile());
        Path encFile = Files.createTempFile("test", ".tmp");
        Path decFile = Files.createTempFile("test", ".tmp");

        try {
            try (InputStream in = Files.newInputStream(srcFile, StandardOpenOption.READ)) {
                try (OutputStream out = Files.newOutputStream(encFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                    encrypt.encrypt(key, in, out);
                }
            }

            try (InputStream in = Files.newInputStream(encFile, StandardOpenOption.READ)) {
                try (OutputStream out = Files.newOutputStream(decFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                    encrypt.decrypt(key, in, out);
                }
            }

            assertThat(fileCompare(decFile, srcFile), is(true));
        } finally {
            Files.delete(encFile);
            Files.delete(decFile);
        }
    }

    private boolean fileCompare(Path decFile, Path srcFile) throws IOException {
        try (InputStream in1 = Files.newInputStream(decFile)) {
            try (InputStream in2 = Files.newInputStream(srcFile)) {
                if (in1.read() != in2.read()) {
                    return false;
                }
            }
        }
        return true;
    }
}