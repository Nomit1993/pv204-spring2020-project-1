package simpleapdu;

import applets.SimpleApplet;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
 

public class SimpleAPDU 
{
    static CardMngr cardManager = new CardMngr();
    
    //ECDH Parameters
    static byte[] baTempA = new byte[17];
    static byte[] baTempB = new byte[17];
    static byte[] baTempP = new byte[17];
    static byte[] baTempW = new byte[33];
    static byte[] baTempS = new byte[17];
    static byte[] baTempSS = new byte[17];
    static byte[] baTempSS1 = new byte[17];
    static short lenA, lenB, lenP, lenW, lenS, lenSS;
    static KeyPair kpV;
    static ECPrivateKey privKeyV;
    static ECPublicKey pubKeyV;
    static KeyAgreement ecdhV;
    private static byte baPrivKeyV[] = new byte[17];
    private static byte baPubKeyV[] = new byte[17];
    static private byte baPubKeyU[] = new byte[17];
    static String pin;
    static byte[] hashBuffer = new byte[20];
    
    private static final byte APPLET_AID[] = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x06, (byte) 0xC9, (byte) 0xAA, (byte) 0x4E, (byte) 0x15, (byte) 0xB3, (byte) 0xF6, (byte) 0x7F};

    public static void main(String[] args) throws Exception 
    {
        byte[] installData = new byte[10];
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            
        String data = javax.xml.bind.DatatypeConverter.printHexBinary(APPLET_AID);
        System.out.println(data);
        System.out.println(CardMngr.bytesToHex(APPLET_AID));

        ecdh();
    }    
    
    public static void ecdh() throws Exception
    {
        System.out.println("********************V parameters (PC Side)********************");
            
        InputStreamReader r = new InputStreamReader(System.in);
        BufferedReader br = new BufferedReader(r);
        System.out.println("Enter PIN (PC): ");
        pin= br.readLine();
        System.out.print("PIN (PC): " + pin);
        System.out.println();
            
        if(pin.compareTo("1234") != 0)
        {
            System.out.println("Invalid PIN");
            System.exit(0);
        }
        
        if(pin.length() != 4)
        {
            System.out.println("Invalid PIN");
            System.exit(0);
        }
            
        MessageDigest m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
        m_hash.doFinal(pin.getBytes(),(short)0,(short)pin.getBytes().length,hashBuffer,(short)0);
        System.out.print("HASH OF PIN: ");
        for (byte b: hashBuffer) System.out.print(String.format("%X",b));
        System.out.println();
                    
        kpV = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpV.genKeyPair();
        privKeyV = (ECPrivateKey) kpV.getPrivate();
        pubKeyV = (ECPublicKey) kpV.getPublic();
        
        System.out.println("Key Pair Generation (V)");
        lenA = pubKeyV.getA(baTempA,(short) 0); 
        System.out.print("A (V) " + lenA + " :"); 
        for (byte b: baTempA) System.out.print(String.format("%02X", b)); 
            
        System.out.println();
        lenB = pubKeyV.getB(baTempB,(short) 0); 
        System.out.print("B (V) " + lenB + " :"); 
        for (byte b: baTempB) System.out.print(String.format("%02X", b));
        
        System.out.println();
        lenP = pubKeyV.getField(baTempP, (short) 0); 
        System.out.print("P (V) " + lenP + " :"); 
        for (byte b: baTempP) System.out.print(String.format("%02X", b));
            
        System.out.println();
        lenW = pubKeyV.getW(baTempW,(short) 0); 
        System.out.print("Public Key (V) " + lenW + " :"); 
        for (byte b: baTempW) System.out.print(String.format("%02X", b));

        System.out.println();
        lenS = privKeyV.getS(baTempS,(short) 0);
        System.out.print("Private Key (V) " + lenS + " :");
        for (byte b: baTempS) System.out.print(String.format("%02X", b));
        System.out.println();
            
        byte pu[] = new byte[CardMngr.HEADER_LENGTH];
        pu[CardMngr.OFFSET_CLA] = (byte) 0x00;
        pu[CardMngr.OFFSET_INS] = (byte) 0xD1;
        pu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pu[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] pus = cardManager.sendAPDUSimulator(pu);
        baPubKeyU = Arrays.copyOfRange(pus, 0, 33);
        System.out.println();
        System.out.print("Public Key Received from Card (U) " + baPubKeyU.length + " :");
        for (byte b: baPubKeyU) System.out.print(String.format("%02X", b));
        System.out.println();
            
        byte ss[] = new byte[CardMngr.HEADER_LENGTH + lenW];
        ss[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss[CardMngr.OFFSET_INS] = (byte) 0xD2;
        ss[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(baTempW, 0, ss, 5, lenW);
        byte[] sss = cardManager.sendAPDUSimulator(ss);
        baTempSS1 = Arrays.copyOfRange(sss, 0, 17);
        System.out.println();
        System.out.print("Shared Secret Received from Card (U) " + baTempSS1.length + " :");
        for (byte b: baTempSS1) System.out.print(String.format("%02X", b));
        System.out.println();
            
        Util.arrayCopyNonAtomic(baTempS, (short) 0, baPrivKeyV, (short) 0, (short) lenS);
        
        ecdhV = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, true);
        ecdhV.init(privKeyV);
        lenSS = ecdhV.generateSecret(baPubKeyU, (short)0, lenW, baTempSS, (short) 0);
        System.out.println();
        System.out.print("Shared Secred U and V (V) " + lenSS + " :");
        for (byte b: baTempSS) System.out.print(String.format("%02X", b));
        System.out.println();
            
        System.out.println("Shared Secret Equality: " + Arrays.equals(baTempSS, baTempSS1));
        System.out.println();
        
        byte ss1[] = new byte[CardMngr.HEADER_LENGTH + lenW];
        ss1[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss1[CardMngr.OFFSET_INS] = (byte) 0xD3;
        ss1[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss1[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss1[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] sss1 = cardManager.sendAPDUSimulator(ss1);
        
        byte ss2[] = new byte[CardMngr.HEADER_LENGTH + lenW];
        ss2[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss2[CardMngr.OFFSET_INS] = (byte) 0xD4;
        ss2[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss2[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss2[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] sss2 = cardManager.sendAPDUSimulator(ss2);
        
        //if(Arrays.equals(baTempSS, baTempSS1) == true)
        //start();        
        //G = Hash(PIN) mod P
        //U = (G ^ A) mod P
        //V = (G ^ B) mod P
        //Hash(PIN) = hashBuffer
        
        aes();
    }

    public static void aes() throws Exception
    {
        AESKey aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        byte[] input = {(byte)0x44,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,0x10,(byte)0xA2, 0x35, (byte)0x5E,0x15,0x16,0x14};
        byte[] output = new byte[16];
        short len = (short) input.length;

        System.out.print("Input: ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();
        
        aesKeyTrial.setKey(baTempSS,(short)0);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(input, (short)0, len, output, (short)0); 
        System.out.print("Output: ");
        for (byte b: output) System.out.print(String.format("%02X", b));
        System.out.println();
        
        byte[] input1 = new byte[16];
        aesKeyTrial.setKey(baTempSS,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(output, (short)0, len, input1, (short)0);
        System.out.print("Input Once Again: ");
        for (byte b: input1) System.out.print(String.format("%02X", b));
        System.out.println();
    }
}
