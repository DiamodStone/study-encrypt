package alvin.encrypt.util;

import org.apache.commons.codec.binary.Hex;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public final class CAUtil {

    private CAUtil() {
    }

    public static byte[] publicKeyFromCertificateFile(Path certificateFile) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        try (InputStream in = Files.newInputStream(certificateFile)) {
            Certificate certificate = certificateFactory.generateCertificate(in);
            return certificate.getPublicKey().getEncoded();
        }
    }

    public static byte[] privateKeyFromKeyStore(Path keyStoreFile, String aliaesName, String keyStorePasswd) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keyStoreFile)) {
            keyStore.load(in, keyStorePasswd.toCharArray());
            PrivateKey privateKey = (PrivateKey) (keyStore.getKey(aliaesName, keyStorePasswd.toCharArray()));
            return privateKey.getEncoded();
        }
    }

    public static String publicKeyFromCertificateFileAsString(Path certificateFile) throws Exception {
        return Hex.encodeHexString(publicKeyFromCertificateFile(certificateFile));
    }

    public static String privateKeyFromKeyStoreAsString(Path keyStoreFile, String aliaesName, String keyStorePasswd) throws Exception {
        return Hex.encodeHexString(privateKeyFromKeyStore(keyStoreFile, aliaesName, keyStorePasswd));
    }
}
