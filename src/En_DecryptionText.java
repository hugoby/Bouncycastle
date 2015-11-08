/**
 * Package_name ${PACKAGE_NAME}
 * Project_name Bouncycastle
 * Created by hugo on 2015/10/26 22:48
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


//@�ü��ܷ���ֻ�ܼ��ܵ����ַ���
public class En_DecryptionText {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, IOException, SignatureException {
        //��������ʱ��
        long startTime=System.nanoTime();
        //�����ı�
        String text = "Hugo";
        System.out.println("The text before being encrypted is : " + text);
        //��Կ������
        setECCKey();

        BASE64Decoder decoder2 = new BASE64Decoder();
        byte[] text2 = decoder2.decodeBuffer(text);
        //����
        String textAfterEncrypted = encryption(text2);
        System.out.println("The text after being encrypted is : " + textAfterEncrypted);

        System.out.println("The text after being decrypted is : " + textAfterEncrypted);
        //����
        String textAfterDecrypted = decryption(textAfterEncrypted);
        System.out.println("The text after being encrypted is : " + textAfterDecrypted);

        String signature=setSignature(text);
        System.out.println("The signature is: "+signature);
        if(isRightSignature(textAfterDecrypted,signature))
            System.out.println("The signature is right.");
        long endTime=System.nanoTime();
        System.out.println(endTime-startTime);
    }

    //������Կ����Կ��˽Կ������������HashMap<String,String>keyMap��
    private static void setECCKey() throws NoSuchProviderException, NoSuchAlgorithmException
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 1);//��ʽ��Ӱ�ȫ�ṩ��
        //Map<String,String>keyMap=new HashMap<String,String>();//����һ��ͼ�洢��Կ��
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES", "BC");//ָ����ȫ�ṩ��
        kpg.initialize(256);//������Կ����Ϊ116λ
        KeyPair keyPair = kpg.generateKeyPair();//��ȡ��Կ��
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();//��ȡ��Կ
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();//��ȡ��Կ
        keyMap.put("ECCPUBLICKEY", Base64.toBase64String(publicKey.getEncoded()));//����Կת��ΪBase64String���ַ�����ʽ���洢��Map��
        keyMap.put("ECCPRIVATEKEY", Base64.toBase64String(privateKey.getEncoded()));//����Կת��ΪBase64String���ַ�����ʽ���洢��Map��
    }

    //��ȡ��Կ
    private static ECPublicKey getECCPublicKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPublicKey = "ECCPUBLICKEY";
        byte[] eccPublicKey2 = (Base64.decode(keyMap.get(eccPublicKey)));//����
        X509EncodedKeySpec X509PublicKeyObject = new X509EncodedKeySpec(eccPublicKey2);//����X509EncodedKeySpec��ʽ����Կ�淶
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//��ȡ��Կ��������
        return (ECPublicKey) keyFactory.generatePublic(X509PublicKeyObject);
    }

    //��ȡ˽Կ
    private static ECPrivateKey getECCPrivateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        String eccPrivateKey = "ECCPRIVATEKEY";
        byte[] eccPrivateKey2 = (Base64.decode(keyMap.get(eccPrivateKey)));//����
        PKCS8EncodedKeySpec PKCS8PrivateKeyObject = new PKCS8EncodedKeySpec(eccPrivateKey2);//����PKCS8EncodedKeySpec��ʽ����Կ�淶
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH", "BC");//��ȡ��Կ��������
        return (ECPrivateKey) keyFactory.generatePrivate(PKCS8PrivateKeyObject);
    }

    //����
    private static String encryption(byte[] text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ECPublicKey eccPublicKey = getECCPublicKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//��ȡ�����������
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);//��ʼ������ģʽ�͹�Կ
        byte[] cipherText = cipher.doFinal(text);//����
        return Base64.toBase64String(cipherText);
    }

    //����
    private static String decryption(String text) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        ECPrivateKey eccPrivateKey = getECCPrivateKey();
        Cipher cipher = Cipher.getInstance("ECIES", "BC");//��ȡ�����������
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);//��ʼ������ģʽ��˽Կ
        //�����Ľ���Base64����

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] text3 = decoder.decodeBuffer(text);
        byte[] text4 = cipher.doFinal(text3);//����
        return Base64.toBase64String(text4);
    }

    private static String setSignature(String text) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        ECPrivateKey eccPrivateKey = getECCPrivateKey();
        Signature signature = Signature.getInstance("ECDSA", "BC");
        signature.initSign(eccPrivateKey);
        byte[] text2=text.getBytes();
        signature.update(text2);
        byte[] sign=signature.sign();
        return Base64.toBase64String(sign);
    }

    private static boolean isRightSignature(String text,String sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, IOException
    {
        ECPublicKey eccPublicKey=getECCPublicKey();
        Signature signature=Signature.getInstance("ECDSA","BC");
        signature.initVerify(eccPublicKey);
        byte[] text2=text.getBytes();
        signature.update(text2);
        BASE64Decoder decoder=new BASE64Decoder();
        byte[] sign2=decoder.decodeBuffer(sign);
        return signature.verify(sign2);
    }

    public static HashMap<String, String> keyMap = new HashMap<String, String>();
}






