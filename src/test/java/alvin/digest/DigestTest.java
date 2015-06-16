package alvin.digest;

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
        assertThat(digest.toString(data), is("7acedd1a84a4cfcb6e7a16003242945e"));

        data[50]++;
        assertThat(digest.toString(data), is("e17805819b3512436b9f9269f6aa512b"));
    }

    @Test
    public void test_md5_with_string() throws Exception {
        Digest digest = new Digest("MD5");

        assertThat(digest.toString("hello", "utf-8"), is("5d41402abc4b2a76b9719d911017c592"));
        assertThat(digest.toString("Hello", "utf-8"), is("8b1a9953c4611296a827abf8c47804d7"));
    }

    @Test
    public void test_md5_with_stream() throws Exception {
        Digest digest = new Digest("MD5");

        Path path = Paths.get(DigestTest.class.getResource("/photo-1.jpg").getFile());
        String result1 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result1, is("b5745948dd3ca6669039d6e847137545"));

        path = Paths.get(DigestTest.class.getResource("/photo-2.jpg").getFile());
        String result2 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result2, is(result1));
    }

    @Test
    public void test_sha1_with_stream() throws Exception {
        Digest digest = new Digest("SHA-512");

        Path path = Paths.get(DigestTest.class.getResource("/photo-1.jpg").getFile());
        String result1 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result1, is("469ce380ff4f5e942b047225682050c36752c18987374c0888a2caeec1564f43926baf3" +
                "596516c4d4f1279174c05669778d9ab9219c56cb896ec62d8d5a4c213"));
        path = Paths.get(DigestTest.class.getResource("/photo-2.jpg").getFile());
        String result2 = digest.toString(Files.newInputStream(path, StandardOpenOption.READ));
        assertThat(result2, is(result1));
    }
}