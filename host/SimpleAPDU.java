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
import java.math.BigInteger; 
import java.util.Random;

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
            
        /*if(pin.compareTo("1234") != 0)
        {
            System.out.println("Invalid PIN");
            System.exit(0);
        }*/
        
        if(pin.length() != 4 || !pin.matches("[0-9]+"))
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
        
        byte ss1[] = new byte[CardMngr.HEADER_LENGTH];
        ss1[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss1[CardMngr.OFFSET_INS] = (byte) 0xD3;
        ss1[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss1[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss1[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] sss1 = cardManager.sendAPDUSimulator(ss1);
        
        byte ss2[] = new byte[CardMngr.HEADER_LENGTH];
        ss2[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss2[CardMngr.OFFSET_INS] = (byte) 0xD4;
        ss2[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss2[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss2[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] sss2 = cardManager.sendAPDUSimulator(ss2);
        
        //if(Arrays.equals(baTempSS, baTempSS1) == true)
        //start();        
        //G = Hash(PIN) mod P ---- DONE
        //U = (G ^ A) mod     ---- DONE
        //V = (G ^ B) mod P   ---- DONE
        //Hash(PIN) = hashBuffer
        
        BigInteger p = new BigInteger(baTempP);
        BigInteger G_number = OS2IP(hashBuffer).mod(p);
        byte G_byte[] = I2OSP(G_number, 16);
        System.out.print("Calculated G (V): ");
        for(byte b:G_byte) System.out.print(String.format("%X",b));
        System.out.println();
        
        Random rand = new Random();
	int  A = rand.nextInt(100) + 100;
        BigInteger G_a = G_number.pow(A).mod(p);
        // send G_a to card
        
        // recieve G_b from card
        //G_b =
        // test correct range
        BigInteger LowRange = new BigInteger("2");
        BigInteger HighRange = new BigInteger(""+p.subtract(LowRange));
        if (G_b.compareTo(LowRange) < 0 || G_b.compareTo(HighRange) > 0)
        {
            System.out.println("G_b not in correct range");
            System.exit(0);
        }
        BigInteger K = G_b.pow(A).mod(p);
        
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
    
    // helper functions for SPEKE calculations [IEE163] [https://github.com/chetan51/ABBC/blob/master/src/main/java/RSAEngine/Crypter.java]
    public static BigInteger OS2IP(byte[]X)
    {
        BigInteger out = new BigInteger("0");
        BigInteger twofiftysix = new BigInteger("256");

	for(int i = 1; i <= X.length; i++)
        {
            out = out.add((BigInteger.valueOf(0xFF & X[i - 1])).multiply(twofiftysix.pow(X.length-i)));
	}
	//x = x(xLen–1)^256xLen–1 + x(xLen–2)^256xLen–2 + … + x(1)^256 + x0
	return out;
    }


    public static byte[] I2OSP(BigInteger X, int XLen)
    {
        BigInteger twofiftysix = new BigInteger("256");
	byte[] out = new byte[XLen];
        BigInteger[] cur;

        if(X.compareTo(twofiftysix.pow(XLen)) >= 0)
        {
		return new String("integer too large").getBytes();		
        }
	
        for(int i = 1; i <= XLen; i++)
        {
            cur = X.divideAndRemainder(twofiftysix.pow(XLen-i));
            //X = cur[1];
            out[i - 1] = cur[0].byteValue();
        }
	//basically the inverse of the above
	//Cur is an array of two bigints, with cur[0]=X/256^(XLen-i) and cur[1]=X/256^[XLen-i]
        return out;
    }
}
