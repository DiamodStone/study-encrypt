package alvin.encrypt.util;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

public class RSADemo {

    public long RSA(int baseNum, int key, long message) {
        if (baseNum < 1 || key < 1) {
            return 0L;
        }
        // 加密核心算法
        return (long) Math.pow(message, key) % baseNum;
    }

    @Test
    public void test_rsa_demo() {
        /*
        1. 假设 p = 3、q = 11 (p，q互质)，则 N = pq = 33
        2. 根据欧拉公式，可得 r = (p - 1)(q - 1) = (3 - 1)(11 - 1) = 20
        3. 根据计算公式可以得出，ed ≡ 1 (mod 20), 即 ed = 20n + 1 (n为正整数)；
           假设 n = 1，则ed = 21。e、d为正整数，并且e与r互质，则e = 3，d = 7(两个数交换一下也可以)
        4. 到这里，公钥和密钥已经确定。公钥为(N, e) = (33, 3)，密钥为(N, d) = (33, 7)
         */
        // 基数
        int baseNum = 3 * 11;

        // 公钥
        int keyE = 3;
        // 密钥
        int keyD = 7;

        // 未加密的数据
        long msg = 24L;

        // 加密后的数据
        long encodeMsg = RSA(baseNum, keyE, msg);
        assertThat(encodeMsg, not(msg));

        // 解密后的数据
        long decodeMsg = RSA(baseNum, keyD, encodeMsg);
        assertThat(decodeMsg, is(msg));
    }
}
