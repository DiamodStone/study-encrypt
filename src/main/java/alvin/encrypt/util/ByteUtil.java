package alvin.encrypt.util;

public final class ByteUtil {

    private static final char HEX_DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private ByteUtil() {
    }

    public static String byteArrayToString(byte[] data) {
        char[] output = new char[data.length * 2];
        int pos = 0;
        for (byte b : data) {
            output[pos++] = HEX_DIGITS[b >>> 4 & 0xF];
            output[pos++] = HEX_DIGITS[b & 0xF];
        }
        return new String(output);
    }

    public static byte[] stringToByteArray(String data) {
        byte[] result = new byte[data.length() / 2];
        for (int i = 0; i < data.length(); ) {
            int b = 0;
            for (int j = 0; j < 2; j++) {
                b *= 16;
                char c = data.charAt(i++);
                switch (c) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    b += (byte) (c - '0');
                    break;
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                    b += (byte) (c - 'a' + 10);
                    break;
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    b += (byte) (c - 'A' + 10);
                    break;
                default:
                    throw new IllegalArgumentException(data);
                }
            }
            result[(i >>> 1) - 1] = (byte) b;
        }
        return result;
    }
}
