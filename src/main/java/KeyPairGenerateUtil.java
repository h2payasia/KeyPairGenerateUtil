import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyPairGenerateUtil {

    /**
     * 指定加密算法为RSA
     */
    public static final String ALGORITHM = "RSA";

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static final String PRIVATE_TYPE = "PRIVATE KEY";
    public static final String PUBLIC_TYPE = "PUBLIC KEY";
    /**
     * 密钥长度，用来初始化
     */
    private static final int KEYSIZE = 2048;


    public static void main(String[] args) throws Exception {

        // generate keyPair
        KeyPair keyPair = generateKeyPair();

        //print private key string
        String privateKeyString = new BASE64Encoder().encode(keyPair.getPrivate().getEncoded());
        System.out.println("private key:");
        System.out.println(privateKeyString);
        System.out.println();
        //print public key string
        String publicKeyString = new BASE64Encoder().encode(keyPair.getPublic().getEncoded());
        System.out.println("public key:");
        System.out.println(publicKeyString);

        //save private key with PKCS8
        JcaPEMWriter privatepemWriter = new JcaPEMWriter(Files.newBufferedWriter(Paths.get("privateKey.pem"), StandardCharsets.UTF_8));
        privatepemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
        privatepemWriter.close();

        //save public key PKCS8
        PemObject pemObject = new PemObject(KeyPairGenerateUtil.PUBLIC_TYPE, keyPair.getPublic().getEncoded());
        try (PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(Paths.get("publicKey.pem"), StandardCharsets.UTF_8))) {
            pemWriter.writeObject(pemObject);
        }

        System.out.println();

        // load private key
        String priFile = "privateKey.pem";
        privateKeyString = loadPriFromFile(priFile);
        System.out.println("loaded private key:");
        System.out.println(privateKeyString);
        System.out.println();

        // load public key
        String pubFile = "publicKey.pem";
        publicKeyString = loadPubFromFile(pubFile);
        System.out.println("loaded public key:");
        System.out.println(publicKeyString);

        String plainText = "the h2 demo";
        //sign with private key
        String signature = sign(plainText.getBytes(StandardCharsets.UTF_8), privateKeyString);
        System.out.println("signature:");
        System.out.println(signature);
        System.out.println();
        //verify with public key
        System.out.println("verify:");
        System.out.println(verify(plainText.getBytes(StandardCharsets.UTF_8), publicKeyString, signature));
        System.out.println();

        //encrypt with public key
        String encrypt = encrypt(plainText, publicKeyString);
        System.out.println("encrypt:");
        System.out.println(encrypt);
        System.out.println();

        //decrypt with private key
        String decrypt = decrypt(encrypt, privateKeyString);
        System.out.println("decrypt:");
        System.out.println(decrypt);


    }



    public static KeyPair generateKeyPair() {

        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom secureRandom = new SecureRandom();

        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        keyPairGenerator.initialize(KEYSIZE, secureRandom);

        /** 生成密匙对 */
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 用私钥对信息进行数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥-base64加密的
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey priKey = factory.generatePrivate(keySpec);// 生成私钥
        // 用私钥对信息进行数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);
        return new String(Base64.getEncoder().encode(signature.sign()), StandardCharsets.UTF_8);

    }

    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(Base64.getDecoder().decode(sign)); // 验证签名
    }

    public static String loadPubFromFile(String fileName) {
        PemObject pemObject = null;
        try (PemReader pemReader = new PemReader(new InputStreamReader(Files.newInputStream(Paths.get(fileName))))) {
            pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec kspec = new X509EncodedKeySpec(content);

            KeyFactory kf = KeyFactory.getInstance(KeyPairGenerateUtil.ALGORITHM);
            PublicKey publicKey = kf.generatePublic(kspec);
            String priEncBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            return priEncBase64;
        } catch (Exception e) {

            return null;
        }
    }

    public static String loadPriFromFile(String fileName) throws IOException, PKCSException {

        Security.addProvider(new BouncyCastleProvider());

        PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(fileName)));
        PrivateKeyInfo encryptedKeyPair = (PrivateKeyInfo) pemParser.readObject();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PrivateKey privateKey = converter.getPrivateKey(encryptedKeyPair);
        String priEncBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        return priEncBase64;

    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws Exception                 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        // base64编码的公钥
        byte[] keyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(keyBytes));
        // RSA加密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        return Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }


    /**
     * RSA私钥解密
     *
     * @param encryStr   加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws Exception                 解密过程中的异常信息
     */
    public static String decrypt(String encryStr, String privateKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        // base64编码的私钥
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
        // RSA解密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, priKey);

        // 64位解码加密后的字符串
        byte[] data = Base64.getDecoder().decode(encryStr.getBytes(StandardCharsets.UTF_8));
        String outStr = new String(cipher.doFinal(data));
        return outStr;

    }


}