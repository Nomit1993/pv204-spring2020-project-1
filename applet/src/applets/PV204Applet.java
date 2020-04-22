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
import java.util.Random;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
import static simpleapdu.SimpleAPDU.bigintegertobyte;
import static simpleapdu.SimpleAPDU.bytetobiginteger;

public class PV204Applet extends javacard.framework.Applet 
{
    // The APDU class for our applet.
    final static byte CLA_PV204APPLET = (byte) 0xC1;

    // Temporary variables, all stored in volatile RAM.
    int trace = 6;

    static byte[] pinhash = new byte[20];
    
    KeyPair kpU;
    ECPrivateKey privKeyU;
    ECPublicKey pubKeyU;

    short lenA, lenB, lenP, lenPubK, lenPvtK, lenSS;
    
    byte[] baTempA = new byte[17];
    byte[] baTempB = new byte[17];
    byte[] baTempP = new byte[17];
    byte[] baTempW = new byte[33];
    byte[] baTempS = new byte[17];
    byte[] k = new byte[17];

    // The PIN is stored persistently in EEPROM because we need it to create the group
    // generator for SPEKE.
    //MATEJ Kindly check here, i have used just one set pin = 1234
    //private byte[] pin = null;

    /**
     * Hidden constructor for the applet.
     *
     * The install method should be called instead.
     *
     * @param buffer Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    protected PV204Applet(byte[] buffer, short offset, byte length) 
    {
        baTempA = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
        baTempB = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
        baTempP = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
        baTempW = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_DESELECT);
        baTempS = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
        k = JCSystem.makeTransientByteArray((short) 25, JCSystem.CLEAR_ON_DESELECT);
        pinhash = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        // Store the PIN.
        //MATEJ Kindly check here
        //pin = new byte[length];
        //Util.arrayCopy(buffer, offset, pin, (short)0, length);
  
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
                case (byte) 0xD1: pinandecdhchannel(apdu); return;
                case (byte) 0xD2: sentKHost(apdu); return;
                case (byte) 0xD3: aescommunication(apdu); return;
                default:    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
            }
        }
        else
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);    
    }
    
    private void pinandecdhchannel(APDU apdu)
    {
        byte pin[] = {0x31,0x32,0x33,0x34};
        System.out.println();
        System.out.print("PIN (CARD): 1234");
        System.out.println();
        
        MessageDigest phash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
        phash.doFinal(pin, (short)0, (short)pin.length, pinhash,(short)0);
        System.out.print("Hash Of PIN (CARD): ");
        for (byte b: pinhash) System.out.print(String.format("%X",b));
        System.out.println();
        
        kpU = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey) kpU.getPrivate();
        pubKeyU = (ECPublicKey) kpU.getPublic();

        lenA = pubKeyU.getA(baTempA,(short) 0);
        lenB = pubKeyU.getB(baTempB,(short) 0);
        lenP = pubKeyU.getField(baTempP, (short) 0);
        lenPubK = pubKeyU.getW(baTempW,(short) 0);
        lenPvtK = privKeyU.getS(baTempS,(short) 0);
        
        byte[] apduBuf = apdu.getBuffer();
        byte[] receivedBHost = Arrays.copyOfRange(apduBuf, 5, lenB + 5);
        
        //CARD --> K = ((G ^ B) ^ A) mod P <--> (G ^ AB) mod P

        BigInteger A = bytetobiginteger(baTempA);
        BigInteger B = bytetobiginteger(receivedBHost);
        BigInteger P = bytetobiginteger(baTempP);
        BigInteger G = bytetobiginteger(pinhash).mod(P);
        BigInteger K = G.modPow(B.multiply(A), P);
        
        k = bigintegertobyte(K, 16);
        System.out.println();
        System.out.print("Shared Secret K (CARD): ");
        for (byte b: k) System.out.print(String.format("%02X", b));
        
        System.out.println();
        System.out.print("Sending Parameter A (to HOST)");
        System.out.println();System.out.println("********************Trace [2]********************");
        Util.arrayCopyNonAtomic(baTempA, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)lenA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)lenA);
    }
        
    private void sentKHost(APDU apdu)
    {
        byte[] apduBuf = apdu.getBuffer();
        
        System.out.println();
        System.out.print("Sending Shared Secret K (to HOST)");
        System.out.println();System.out.println("********************Trace [4]********************");
        Util.arrayCopyNonAtomic(k, (short) 0, apduBuf, ISO7816.OFFSET_CDATA, (short)k.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)k.length);
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
        
        aesKeyTrial.setKey(k,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(encinput, (short)0, (short)encinput.length, decinput, (short)0);
        
        System.out.print("Decrypted Input: ");
        for (byte b: decinput) System.out.print(String.format("%02X", b));
        System.out.println();
        
        System.out.println();
        System.out.print("Input (CARD): ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();
        
        aesKeyTrial.setKey(k,(short)0);
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
