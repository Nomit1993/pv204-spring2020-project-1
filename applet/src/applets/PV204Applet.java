package applets;

import static applets.SimpleApplet.CLA_SIMPLEAPPLET;
import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class SimpleApplet extends javacard.framework.Applet 
{
    /**
     * Hidden constructor for the applet.
     *
     * The install method should be called instead.
     *
     * @param parameters Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    byte[] baTemp = new byte[255];
    byte[] baTempA = new byte[17];
    byte[] baTempB = new byte[17];
    byte[] baTempP = new byte[17];
    byte[] baTempW = new byte[33];
    byte[] baTempS = new byte[17];
    byte[] baTempSS = new byte[17];
    short lenA, lenB, lenP, lenW, lenS, lenSS;
    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;
    KeyAgreement ecdhU;
    private final MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
    final static byte CLA_SIMPLEAPPLET = (byte) 0x00;
    private byte baPrivKeyU[] = new byte[17];
    private byte baPubKeyU[] = new byte[17];
    private byte baPubKeyV[] = new byte[17];
    
    protected SimpleApplet(byte[] buffer, short offset, byte length) {
        // TODO: Parse the supplied parameters.
        // TODO: Set up and initialize variables for internal use.
        // Register this applet instance via JavaCard.
        register();
    }

    /**
     * Clear sensitive data from memory.
     *
     * Clear session keys, ephemeral keys, etc. that we do not wish others after us
     * to know.
     */
    protected void clearData() {
        // TODO: Clear sensitive data. Overwrite with zeros or random bytes.
    }

    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card upon deselecting the applet. This also clear any sensitive
     * data that might remain the memory.
     */
    public void deselect() {
        clearData();
    }

    /**
     * Install the applet with the given parameters.
     *
     * @param parameters Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    public static void install(byte[] parameters, short offset, byte length)
        throws ISOException
    {
        // NOTE: Return value is ignored. All the necessary configuration happens in
        // the constructor.
        new SimpleApplet(parameters, offset, length);
    }

    /**
     * Process an incoming APDU.
     *
     * @param apdu The APDU to be processed.
     */
    public void process(APDU apdu) throws ISOException {
    
    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card to check before selecting the applet. This also clear any
     * sensitive data that might remain the memory.
     *
     * @return true if applet can be selected; false otherwise.
     */
    byte[] apduBuffer = apdu.getBuffer();
    if (selectingApplet())  return;
    if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) 
    {
        switch (apduBuffer[ISO7816.OFFSET_INS]) 
        {
            case (byte) 0xD1: process1(apdu); return;
            case (byte) 0xD2: process2(apdu); return;
            case (byte) 0xD3: process3(apdu); return;
            case (byte) 0xD4: process4(apdu); return;
            default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
        }
    }
    else
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);    
    }
    
    public boolean select() {
        clearData();

        return true;
    }
    
    private void process1(APDU apdu)
    {
        byte[] apduBuf1 = apdu.getBuffer();

        System.out.println("********************U parameters (Card Side)********************");

        byte pin[] = {0x31,0x32,0x33,0x34};
        System.out.print("PIN Set on Card: 1234");
        System.out.println();
        byte[] hashBuffer = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
        hash.doFinal(pin,(short)0,(short)pin.length,hashBuffer,(short)0);
        System.out.print("HASH OF PIN: ");
        for (byte b:hashBuffer) System.out.print(String.format("%X",b));
        System.out.println();
    
        kpU = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey) kpU.getPrivate();
        pubKeyU = (ECPublicKey) kpU.getPublic();

        System.out.println("Key Pair Generation (U)");
        lenA = pubKeyU.getA(baTempA,(short) 0);
        System.out.print("A (U) " + lenA + " :"); 
        for (byte b: baTempA) System.out.print(String.format("%02X", b)); 

        System.out.println();
        lenB = pubKeyU.getB(baTempB,(short) 0);
        System.out.print("B (U) " + lenB + " :"); 
        for (byte b: baTempB) System.out.print(String.format("%02X", b));

        System.out.println();
        lenP = pubKeyU.getField(baTempP, (short) 0);
        System.out.print("P (U) " + lenP + " :"); 
        for (byte b: baTempP) System.out.print(String.format("%02X", b));
        
        System.out.println();
        lenW = pubKeyU.getW(baTempW,(short) 0);
        System.out.print("Public Key (U) " + lenW + " :"); 
        for (byte b: baTempW) System.out.print(String.format("%02X", b));
       
        System.out.println();
        lenS = privKeyU.getS(baTempS,(short) 0);
        System.out.print("Private Key (U) " + lenS + " :");
        for (byte b: baTempS) System.out.print(String.format("%02X", b));
        System.out.println();
        
        Util.arrayCopyNonAtomic(baTempW, (short) 0, apduBuf1, ISO7816.OFFSET_CDATA, lenW);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, lenW);
    }
    
    private void process2(APDU apdu)
    {
        byte[] apduBuf2 = apdu.getBuffer();

        baPubKeyV = Arrays.copyOfRange(apduBuf2, 5, 38);
        System.out.print("Public Key Received from Host (V) " +lenW + " :");
        for (byte b: baPubKeyV) System.out.print(String.format("%02X", b));
        System.out.println();
       
        Util.arrayCopyNonAtomic(baTempS, (short) 0, baPrivKeyU, (short) 0, (short) lenS);
        
        ecdhU = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ecdhU.init(privKeyU);
        lenSS = ecdhU.generateSecret(baPubKeyV, (short)0, lenW, baTempSS, (short) 0);
        System.out.print("Shared Secred U and V (U) " + lenSS + " :");
        for (byte b: baTempSS) System.out.print(String.format("%02X", b));
        System.out.println();
        
        Util.arrayCopyNonAtomic(baTempSS, (short) 0, apduBuf2, ISO7816.OFFSET_CDATA, (short) baTempSS.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) baTempSS.length);
    }
        
    private void process3(APDU apdu)
    {
        byte[] apduBuf3 = apdu.getBuffer();
    }
    
    private void process4(APDU apdu) 
    {
        byte[] apduBuf4 = apdu.getBuffer();
        byte[] sharedkey = new byte[16];
        Util.arrayCopyNonAtomic(apduBuf4, (short)5, sharedkey, (short)0, (short)16);
  
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
