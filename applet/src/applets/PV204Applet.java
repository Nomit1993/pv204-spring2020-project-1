package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PV204Applet extends javacard.framework.Applet {
    /**
     * Hidden constructor for the applet.
     *
     * The install method should be called instead.
     *
     * @param parameters Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    byte[] baTemp = new byte[255]
    byte[] baPrivKeyU, baPubKeyU, baPubKeyV;
    byte[] baTempA = new byte[17];
    byte[] baTempB = new byte[17];
    byte[] baTempP = new byte[17];
    byte[] baTempW = new byte[33];
    byte[] baTempS = new byte[33];
    byte[] baTempSS = new byte[17];
    short lenA, lenB, lenP, lenW, lenS, lenSS;
    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;
    KeyAgreement ecdhU;
    private final MessageDigest m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
    final static byte CLA_SIMPLEAPPLET = (byte) 0x00;
    
    protected PV204Applet(byte[] parameters, short offset, byte length) {
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
    @Override
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
        new PV204Applet(parameters, offset, length);
    }

    /**
     * Process an incoming APDU.
     *
     * @param apdu The APDU to be processed.
     */
    @Override
    public void process(APDU apdu) throws ISOException {
    }

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
            default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
        }
    }
    else
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);    
    
    @Override
    public boolean select() {
        clearData();

        return true;
    }
    
    private void processINSD1(APDU apdu)
    {
        System.out.println("********************U parameters (Card Side)********************");

        byte pin[] = {0x31,0x32,0x33,0x34};
        System.out.print("PIN Set on Card: 1234");
        System.out.println();
        byte[] hashBuffer = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
        m_hash.doFinal(pin,(short)0,(short)pin.length,hashBuffer,(short)0);
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
       
        lenS = privKeyU.getS(baTempS,(short) 0);
        baPrivKeyU =new byte[lenS];
        Util.arrayCopyNonAtomic(baTempS, (short)0, baPrivKeyU, (short)0, lenS);
        System.out.println();
        System.out.print("Private Key (U) " + lenS + " :");
        for (byte b: baPrivKeyU) System.out.print(String.format("%02X", b));
        System.out.println();       
    }
}
