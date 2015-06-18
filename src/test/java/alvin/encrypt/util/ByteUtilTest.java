package alvin.encrypt.util;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class ByteUtilTest {

    @Test
    public void test_byte_array_to_string() throws Exception {
        byte[] array = new byte[16];
        for (int i = 0; i < array.length; i++) {
            array[i] = (byte) (i + 0xF0);
        }
        assertThat(ByteUtil.byteArrayToString(array), is("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"));
    }

    @Test
    public void test_string_to_byte_array() throws Exception {
        byte[] result = ByteUtil.stringToByteArray("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        for (int i = 0; i < result.length; i++) {
            assertThat(result[i], is((byte) (i + 0xF0)));
        }
    }
}