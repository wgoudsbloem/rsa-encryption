import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;

public class App {
    public static void main(String[] args) throws Exception {
        String toBeEncrypted = "secret password";
        InputStream pubFile = Files.newInputStream(Paths.get("rsa.pub"));
        byte[] pubFileContent = pubFile.readAllBytes();
        pubFile.close();
        String pubString = new String(pubFileContent);
        pubString = pubString.split(" ")[1];
        // System.out.println(pubString);
        InputStream privFile = Files.newInputStream(Paths.get("rsa"));
        byte[] privFileContent = privFile.readAllBytes();
        privFile.close();
        String privString = new String(privFileContent);
        privString = privString.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                .replace("-----END OPENSSH PRIVATE KEY-----", "").replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        // System.out.println(privString);

        byte[] encrypted = encrypt(toBeEncrypted, pubString);
        System.out.printf("encrypted password:\n%s\n", Hex.encodeHexString(encrypted));
        byte[] decrypted = decrypt(encrypted, privString);
        System.out.printf("to be encrypted: %s\n", toBeEncrypted);
        System.out.printf("decrypted back:  %s\n", new String(decrypted));
    }

    static byte[] encrypt(String toBeEntrypted, String pubKeyString) throws Exception {
        RSAKeyParameters rsa = (RSAKeyParameters) OpenSSHPublicKeyUtil
                .parsePublicKey(Base64.getDecoder().decode(pubKeyString));
        KeySpec keySpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(toBeEntrypted.getBytes("UTF-8"));
    }

    static byte[] decrypt(byte[] encryptedValue, String privKeyString) throws Exception {
        RSAKeyParameters rsa = (RSAKeyParameters) OpenSSHPrivateKeyUtil
                .parsePrivateKeyBlob(Base64.getDecoder().decode(privKeyString));
        KeySpec keySpec = new RSAPrivateKeySpec(rsa.getModulus(), rsa.getExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedValue);
    }

}
