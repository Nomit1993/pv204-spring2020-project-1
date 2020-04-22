package applet;

import javacard.security.*;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javacardx.crypto.Cipher;

public class SimpleApplet extends javacard.framework.Applet {

    int trace = 6;
    private byte secret[] =null;
    final static byte pin[] = {0x31,0x32,0x33,0x34};
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    /**
     * SimpleApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length) 
    {
        register();
    }

    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new SimpleApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
    }

    
    public void process(APDU apdu) throws ISOException 
    {
        byte[] apduBuffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        try
        {
            if (selectingApplet())  
                return;
            
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) 
            {
                switch (apduBuffer[ISO7816.OFFSET_INS]) 
                {
                    case (byte) 0xD1: pinandecdhchannel(apdu, len); return;
                    case (byte) 0xD2: aescommunication(apdu); return;
                    default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
                }
            }
            else
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);                
            }
            
        catch (NoSuchAlgorithmException ex) 
        {
            Logger.getLogger(SimpleApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void pinandecdhchannel(APDU apdu, short len) throws NoSuchAlgorithmException
    {
        byte[] apdubuf = apdu.getBuffer();
        //SECRET= x(S-wN)
        short dataLen = apdu.getIncomingLength(); 
        byte test[]=new byte[dataLen];

        System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA,test,(short)0,dataLen);
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecparams, random));
        AsymmetricCipherKeyPair alicePair = gen.generateKeyPair();
        ECPublicKeyParameters alicepublic = (ECPublicKeyParameters) alicePair.getPublic();
        ECPrivateKeyParameters aliceprivate = (ECPrivateKeyParameters) alicePair.getPrivate();
        ECPoint bigY = alicepublic.getQ();
        BigInteger smally = aliceprivate.getD();
        String s = new String(pin);
        long num = Long.parseLong(s);
        BigInteger PIN = BigInteger.valueOf(num);
        ECPoint bigN = ecparams.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint bigM = ecparams.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
        ECPoint bigT = ecparams.getCurve().decodePoint(test);
        ECPoint shared2 = bigT.subtract(bigM.multiply(PIN)).multiply(smally);
        secret = shared2.getEncoded(true);
        System.out.println();
        System.out.print("Shared Secret K (CARD): ");
        for (byte b: secret) System.out.print(String.format("%02X", b));        
        System.out.println();
        
        //S = Y + wN;
        ECPoint bigS = bigN.multiply(PIN).add(bigY);
        byte[] sentS = bigS.getEncoded(true);
        System.arraycopy(sentS,(short)0,apdubuf,ISO7816.OFFSET_CDATA,sentS.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)sentS.length);
    }
    
    private void aescommunication(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();
        
        AESKey aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        byte[] input = new byte[16];
        new Random().nextBytes(input);
        byte[] encinput = Arrays.copyOfRange(apduBuf, 5, 21);
        byte[] decinput = new byte[16];
        byte[] sentencinput = new byte[16];
        
        System.out.println();
        System.out.print("Encrypted Input (from HOST): ");
        for (byte b: encinput) System.out.print(String.format("%02X", b));
        System.out.println();        
        
        aesKeyTrial.setKey(secret,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(encinput, (short)0, (short)encinput.length, decinput, (short)0);
        
        System.out.print("Decrypted Input: ");
        for (byte b: decinput) System.out.print(String.format("%02X", b));
        System.out.println();
        
        System.out.println();
        System.out.print("Input (CARD): ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();
        
        aesKeyTrial.setKey(secret,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(input, (short)0, (short)input.length, sentencinput, (short)0); 
        
        System.out.print("Encrypted Input (CARD): ");
        for (byte b: sentencinput) System.out.print(String.format("%02X", b));
        
        System.out.println();
        System.out.print("Sending Encrypted Input (to HOST)");
        System.out.println();System.out.println("********************Trace [" + trace + "]********************");
        Util.arrayCopyNonAtomic(sentencinput, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)sentencinput.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)sentencinput.length);
        
        trace = trace + 2;
    }        
}