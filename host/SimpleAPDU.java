package simpleapdu;

import applets.SimpleApplet;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;

public class SimpleAPDU 
{
    static CardMngr cardManager = new CardMngr();
    static byte[] baPrivKeyV, baPubKeyV, baPubKeyU;
    static byte[] baTempA = new byte[17];
    static byte[] baTempB = new byte[17];
    static byte[] baTempP = new byte[17];
    static byte[] baTempW = new byte[33];
    static byte[] baTempS = new byte[33];
    static byte[] baTempSS = new byte[17];
    static byte[] baTempG = new byte[100];
    static short lenA, lenB, lenP, lenW, lenS, lenSS;
    static KeyPair kpV;
    static ECPrivateKey privKeyV;
    static ECPublicKey pubKeyV;
    static KeyAgreement ecdhV;
    
    private static final byte APPLET_AID[] = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x06, (byte) 0xC9, (byte) 0xAA, (byte) 0x4E, (byte) 0x15, (byte) 0xB3, (byte) 0xF6, (byte) 0x7F};
    
    private static void process1()
    {
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
        
        lenS = privKeyV.getS(baTempS,(short) 0);
        baPrivKeyV = new byte[lenS];
        Util.arrayCopyNonAtomic(baTempS, (short)0, baPrivKeyV, (short)0, lenS);
        System.out.println();
        System.out.print("Private Key (V) " + lenS + " :");
        for (byte b: baPrivKeyV) System.out.print(String.format("%02X", b));
        System.out.println();
    }
    
    public static void main(String[] args) throws Exception 
    {
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            
            short additionalDataLenPIN = 4;
            String data = javax.xml.bind.DatatypeConverter.printHexBinary(APPLET_AID);
            System.out.println(data);
            System.out.println(CardMngr.bytesToHex(APPLET_AID));
            
            byte D23[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLenPIN];
            D23[CardMngr.OFFSET_CLA] = (byte) 0x00;// class B0
            D23[CardMngr.OFFSET_INS] = (byte) 0xD1;// for INS_SETPIN
            D23[CardMngr.OFFSET_P1] = (byte) 0x00;// randomly pass Admin PIN byte number
            D23[CardMngr.OFFSET_P2] = (byte) 0x00;// randomply pass Admin PIN byte + 5
            D23[CardMngr.OFFSET_LC] = (byte) 0x00;
            D23[CardMngr.OFFSET_DATA] = (byte) 0x7F;
            byte[] D23sent = cardManager.sendAPDUSimulator(D23);

            System.out.println("********************V parameters (PC Side)********************");
            
            InputStreamReader r = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(r);
            System.out.println("Enter PIN (PC): ");
            String pin= br.readLine();
            System.out.print("PIN (PC): " + pin);
            System.out.println();
            if(pin.length() != 4)
            {
                System.out.println("Invalid PIN");
                System.exit(0);
            }
            MessageDigest m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
            byte[] hashBuffer = new byte[20];//JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
            m_hash.doFinal(pin.getBytes(),(short)0,(short)pin.getBytes().length,hashBuffer,(short)0);
            System.out.print("HASH OF PIN: ");
            for (byte b:hashBuffer) System.out.print(String.format("%X",b));
            System.out.println();
            
            process1();
    }    
}