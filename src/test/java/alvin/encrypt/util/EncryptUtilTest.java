package alvin.encrypt.util;

import org.junit.Test;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

public class EncryptUtilTest {

    @Test
    public void test_des_enc_and_dec() throws Exception {
        final String expectedString = "Hello Java";
        final byte[] expectedData = expectedString.getBytes("UTF-8");

        EncryptUtil encrypt = new EncryptUtil("DESede");

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

        EncryptUtil encrypt = new EncryptUtil("AES");

        String key = encrypt.makeKeyAsString(256);
        byte[] encData = encrypt.encrypt(key, expectedData);

        assertThat(encData.length, greaterThan(expectedData.length));
        assertThat(new String(encData, "UTF-8"), not(expectedString));

        byte[] srcData = encrypt.decrypt(key, encData);
        assertThat(srcData.length, is(expectedData.length));
        assertThat(new String(srcData, "UTF-8"), is(expectedString));
    }
}