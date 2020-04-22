/*
 * Copyright 2020 Matěj Grabovský, Nomit Sharma, Milan Šorf
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package applets;

import java.math.BigInteger;
import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import static host.HostClientApp.bitb;
import static host.HostClientApp.btbi;

public class PV204Applet extends javacard.framework.Applet
{
    // The APDU class for our applet.
    final static byte CLA_PV204APPLET = (byte) 0xC1;

    // Temporary variables, all stored in volatile RAM.
    private byte[] baTempA = null;
    private byte[] baTempB = null;
    private byte[] baTempP = null;
    private byte[] baTempW = null;
    private byte[] baTempS = null;
    private byte[] baTempSS = null;
    private byte[] g = null;
    private byte baPrivKeyU[] = null;
    private byte baPubKeyU[] = null;
    private byte baPubKeyV[] = null;
    private byte[] hashBuffer = null;

    private KeyPair kpU;
    private ECPrivateKey privKeyU;
    private ECPublicKey pubKeyU;
    private KeyAgreement ecdhU;
    private final MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);

    // The PIN is stored persistently in EEPROM because we need it to create the group
    // generator for SPEKE.
    private byte[] pin = null;

    /**
     * Hidden constructor for the applet.
     *
     * The install method should be called instead.
     *
     * @param buffer Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    protected PV204Applet(byte[] buffer, short offset, byte length) {
        baTempA = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baTempB = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baTempP = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baTempW = JCSystem.makeTransientByteArray((short) 33, JCSystem.CLEAR_ON_DESELECT);
        baTempS = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baTempSS = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        g = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);

        baPrivKeyU = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baPubKeyU = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);
        baPubKeyV = JCSystem.makeTransientByteArray((short) 17, JCSystem.CLEAR_ON_DESELECT);

        hashBuffer = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_DESELECT);

        // Store the PIN.
        pin = new byte[length];
        Util.arrayCopy(buffer, offset, pin, (short)0, length);

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
        // Overwrite hash buffer with zeros.
        Util.arrayFillNonAtomic(hashBuffer, (short)0, (short)hashBuffer.length, (byte)0);
        Util.arrayFillNonAtomic(pin, (short)0, (short)pin.length, (byte)0);
        // TODO: Clear more sensitive data if necessary.
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
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_PV204APPLET)
        {
            switch (apduBuffer[ISO7816.OFFSET_INS])
            {
                case (byte) 0xD1: process1(apdu); return;
                case (byte) 0xD2: process2(apdu); return;
                case (byte) 0xD3: process3(apdu); return;
                default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
            }
        }
        else
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    private void process1(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();

        System.out.println("********************U parameters (Card Side)********************");

        hash.doFinal(pin,(short)0,(short)pin.length,hashBuffer,(short)0);
        System.out.print("HASH OF PIN: ");
        for (byte b:hashBuffer) System.out.print(String.format("%X",b));
        System.out.println();

        kpU = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_128);
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey) kpU.getPrivate();
        pubKeyU = (ECPublicKey) kpU.getPublic();

        System.out.println("Key Pair Generation (U)");
        short lenA = pubKeyU.getA(baTempA,(short) 0);
        System.out.print("A (U) " + lenA + " :");
        for (byte b: baTempA) System.out.print(String.format("%02X", b));

        System.out.println();
        short lenB = pubKeyU.getB(baTempB,(short) 0);
        System.out.print("B (U) " + lenB + " :");
        for (byte b: baTempB) System.out.print(String.format("%02X", b));

        System.out.println();
        short lenP = pubKeyU.getField(baTempP, (short) 0);
        System.out.print("P (U) " + lenP + " :");
        for (byte b: baTempP) System.out.print(String.format("%02X", b));

        System.out.println();
        short lenW = pubKeyU.getW(baTempW,(short) 0);
        System.out.print("Public Key (U) " + lenW + " :");
        for (byte b: baTempW) System.out.print(String.format("%02X", b));

        System.out.println();
        short lenS = privKeyU.getS(baTempS,(short) 0);
        System.out.print("Private Key (U) " + lenS + " :");
        for (byte b: baTempS) System.out.print(String.format("%02X", b));
        System.out.println();

        baPubKeyV = Arrays.copyOfRange(apduBuf, 5, lenB + 5);
        System.out.print("B Parameter Received from Host (V) " +lenB + " :");
        for (byte b: baPubKeyV) System.out.print(String.format("%02X", b));
        System.out.println();

        //if(Arrays.equals(baTempSS, baTempSS1) == true)
        //start();
        //G = Hash(PIN) mod P ---- DONE
        //U = (G ^ A) mod P
        //V = (G ^ B) mod P
        //Hash(PIN) = hashBuffer

        BigInteger p = btbi(baTempP);

        BigInteger g1 = btbi(hashBuffer).mod(p);
        g = bitb(g1, 16);

        System.out.print("G (U): ");
        for (byte b: g) System.out.print(String.format("%02X", b));
        System.out.println();

        /*BigInteger a1 = btbi(baPubKeyV);
          Random rand = new Random();
          int a = rand.nextInt(1);
        //System.out.println(a.intValue());
        BigInteger midu = btbi(g).pow(a).mod(p);
        byte[] midU = bitb(midu, 16);

        BigInteger bb = btbi(baTempA);
        BigInteger k1 = btbi(midU).pow(bb.intValue()).mod(p);
        byte[] k = bitb(k1, 16);

        System.out.print("Shared Secret At Card (U) " + k.length + " :");
        for (byte b: k) System.out.print(String.format("%02X", b));
        System.out.println();*/

        Util.arrayCopyNonAtomic(baTempA, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)lenA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)lenA);
    }

    private void process2(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(g, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)g.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)g.length);
    }

    private void process3(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();

        byte[] input = Arrays.copyOfRange(apduBuf, 5, 21);
        short len = (short)input.length;
        byte[] output = new byte[16];
        System.out.print("Received Encrypted Input from Host (U): ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();

        AESKey aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKeyTrial.setKey(g,(short)0);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(input, (short)0, (short)len, output, (short)0);
        System.out.print("Decrypted Input from Host (U): ");
        for (byte b: output) System.out.print(String.format("%02X", b));
        System.out.println();

        byte[] newinput = {(byte)0x43,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,0x10,(byte)0xA2, 0x35, (byte)0x5E,0x15,0x16,0x14};
        System.out.print("New Input (U): ");
        for (byte b: newinput) System.out.print(String.format("%02X", b));
        System.out.println();
        byte[] output1 = new byte[16];
        aesKeyTrial.setKey(g,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(newinput, (short)0, len, output1, (short)0);
        System.out.print("Encrypted Input (U): ");
        for (byte b: output1) System.out.print(String.format("%02X", b));
        System.out.println();

        Util.arrayCopyNonAtomic(output1, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)output1.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)output1.length);
    }

    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card to check before selecting the applet. This also clear any
     * sensitive data that might remain the memory.
     *
     * @return true if applet can be selected; false otherwise.
     */
    @Override
    public boolean select() {
        clearData();

        return true;
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
            // TODO: Throw an exception instead.
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
