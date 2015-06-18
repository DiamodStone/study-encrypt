package alvin.encrypt.util;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class DigestTest {

    @Test
    public void test_md5_with_byte() throws Exception {
        Digest digest = new Digest("MD5");

        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        assertThat(digest.toString(data), is("7ACEDD1A84A4CFCB6E7A16003242945E"));

        data[50]++;
        assertThat(digest.toString(data), is("E17805819B3512436B9F9269F6AA512B"));
    }

    @Test
    public void test_md5_with_string() throws Exception {
        Digest digest = new Digest("MD5");

        assertThat(digest.toString("hello", "utf-8"), is("5D41402ABC4B2A76B9719D911017C592"));
        assertThat(digest.toString("Hello", "utf-8"), is("8B1A9953C4611296A827ABF8C47804D7"));
    }

    @Test
    public void test_md5_with_stream() throws Exception {
        Digest digest = new Digest("MD5");

        Path path = Paths.get(DigestTest.class.getResource("/photo-1.jpg").getFile());
        String result1 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result1, is("B5745948DD3CA6669039D6E847137545"));

        path = Paths.get(DigestTest.class.getResource("/photo-2.jpg").getFile());
        String result2 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result2, is(result1));
    }

    @Test
    public void test_sha1_with_string() throws Exception {
        Digest digest = new Digest("SHA1");

        assertThat(digest.toString("hello", "utf-8"), is("AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"));
        assertThat(digest.toString("Hello", "utf-8"), is("F7FF9E8B7BB2E09B70935A5D785E0CC5D9D0ABF0"));
    }

    @Test
    public void test_sha512_with_stream() throws Exception {
        Digest digest = new Digest("SHA-512");

        Path path = Paths.get(DigestTest.class.getResource("/photo-1.jpg").getFile());
        String result1 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result1, is("469CE380FF4F5E942B047225682050C36752C18987374C0888A2CAEEC1564F43926BAF3" +
                "596516C4D4F1279174C05669778D9AB9219C56CB896EC62D8D5A4C213"));
        path = Paths.get(DigestTest.class.getResource("/photo-2.jpg").getFile());
        String result2 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result2, is(result1));
    }
}