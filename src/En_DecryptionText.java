/**
 * Created by hugoby on 2015/10/26.
 */
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.util.HashMap;
import java.security.KeyPairGenerator;


public class En_DecryptionText {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, IOException
    {
        //测试文本
        String text = new String("Hugo majors in SoftWare Engineering in South China University of Technology.");
        System.out.println("The text before being encrypted is : " + text);
        //密钥的生成
        setECCKey();

        BASE64Decoder decoder2 = new BASE64Decoder();
        byte[] text2 = decoder2.decodeBuffer(text);
        //加密
        String textAfterEncrypted = encryption(text2);
        System.out.println("The text after being encrypted is : " + textAfterEncrypted);

        System.out.println("The text after being decrypted is : " + textAfterEncrypted);
        //解密
        String textAfterDecrypted = decryption(textAfterEncrypted);
        System.out.println("The text after being encrypted is : " + textAfterDecrypted);
    }

    //生成密钥（公钥和私钥），并保存在HashMap<String,String>keyMap中
    private static void setECCKey() throws NoSuchProviderException, NoSuchAlgorithmException
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 1);//显式添加安全提供者
        //Map<String,String>keyMap=new HashMap<String,String>();//建立一个图存储密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES", "BC");//指明安全提供者
        kpg.initialize(256);//设置密钥长度为116位
        KeyPair keyPair = kpg.generateKeyPair();//获取密钥对
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();//获取公钥
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();//获取密钥
        keyMap.put("ECCPUBLICKEY", Base64.toBase64String(publicKey.getEncoded()));//将密钥转换为Base64String的字符串格式并存储在Map中
        keyMap.put("ECCPRIVATEKEY", Base64.toBase64String(privateKey.getEncoded()));//将公钥转换为Base64String的字符串格式并存储在Map中
    }

    //获取公钥
    private static ECPublicKey getECCPublicKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPublicKey = new String("ECCPUBLICKEY");
        byte[] eccPublicKey2 = (Base64.decode(keyMap.get(eccPublicKey)));//解码
        X509EncodedKeySpec X509PublicKeyObject = new X509EncodedKeySpec(eccPublicKey2);//生成X509EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        ECPublicKey eccPublicKey3 = (ECPublicKey) keyFactory.generatePublic(X509PublicKeyObject);//生成公钥
        return eccPublicKey3;
    }

    //获取私钥
    private static ECPrivateKey getECCPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPrivateKey = new String("ECCPRIVATEKEY");
        byte[] eccPrivateKey2 = (Base64.decode(keyMap.get(eccPrivateKey)));//解码
        PKCS8EncodedKeySpec PKCS8PrivateKeyObject = new PKCS8EncodedKeySpec(eccPrivateKey2);//生成PKCS8EncodedKeySpec格式的密钥规范
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//获取密钥工厂对象
        ECPrivateKey eccPrivateKey3 = (ECPrivateKey) keyFactory.generatePrivate(PKCS8PrivateKeyObject);//生成私钥
        return eccPrivateKey3;
    }

    //加密
    private static String encryption(byte[] text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ECPublicKey eccPublicKey = getECCPublicKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);//初始化加密模式和公钥
        byte[] cipherText = cipher.doFinal(text);//加密
        String text3 = Base64.toBase64String(cipherText);
        return text3;
    }

    //解密
    private static String decryption(String text) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        ECPrivateKey eccPrivateKey = getECCPrivateKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//获取密码引擎对象
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);//初始化解密模式和私钥
        //对密文进行Base64解码
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] text3 = decoder.decodeBuffer(text);

        byte[] text4 = cipher.doFinal(text3);//解密
        String text5 = Base64.toBase64String(text4);
        return text5;
    }

    public static HashMap<String, String> keyMap = new HashMap<String, String>();


    private static void signature(byte[] text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        ECPrivateKey eccPpivateKey = getECCPrivateKey();
        Signature signature = Signature.getInstance("ECIES", "BC");
        signature.initSign(eccPpivateKey);
        signature.update(text);
    }
}
