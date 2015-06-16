package alvin.util;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class ByteUtilsTest {

    @Test
    public void test_byte_array_to_string() throws Exception {
        byte[] array = new byte[16];
        for (int i = 0; i < array.length; i++) {
            array[i] = (byte) (i + 0xF0);
        }
        assertThat(ByteUtils.byteArrayToString(array), is("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
    }

    @Test
    public void test_string_to_byte_array() throws Exception {
        byte[] result = ByteUtils.stringToByteArray("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        for (int i = 0; i < result.length; i++) {
            assertThat(result[i], is((byte) (i + 0xF0)));
        }
    }
}