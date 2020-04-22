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

public class PV204Applet extends javacard.framework.Applet
{
    // The APDU class for our applet.
    final static byte CLA_PV204APPLET = (byte) 0xC1;
    // Size of integers in the EC prime field in bytes.
    final static short FIELD_SIZE = 25;
    // Digest size of the hash function = 256 bits.
    final static short HASH_SIZE = 32;
    // Length of the PIN in bytes.
    final static short PIN_LENGTH = 4;

    // Clean-slate state before any information is exchanged.
    final private static byte READY = 0x00;
    // Public keys have been exchanged and a session key has been established.
    final private static byte SESSION_KEY_ESTABLISHED = 0x01;
    // Knowledge of key (PIN) has been confirmed.
    final private static byte KEY_CONFIRMED = 0x02;

    // Temporary variables, all stored in volatile RAM.
    private byte[] baTempW = null;
    private byte[] hostW = null;
    private byte[] g = null;
    private byte baPrivKeyU[] = null;
    private byte baPubKeyU[] = null;
    private byte baPubKeyV[] = null;
    private byte sessionKey[] = null;
    private short lenSessionKey = 0;

    private KeyPair kpU;
    private ECPrivateKey privKeyU;
    private ECPublicKey pubKeyU;
    private KeyAgreement ecdhU;

    private byte currentState = READY;

    // The PIN is stored persistently in EEPROM because we need it to create the group
    // generator for SPEKE.
    private byte[] pinHash = null;

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
        baTempW = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_DESELECT);
        hostW = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_DESELECT);
        g = JCSystem.makeTransientByteArray((short) FIELD_SIZE, JCSystem.CLEAR_ON_DESELECT);

        baPrivKeyU = JCSystem.makeTransientByteArray((short) FIELD_SIZE, JCSystem.CLEAR_ON_DESELECT);
        baPubKeyU = JCSystem.makeTransientByteArray((short) FIELD_SIZE, JCSystem.CLEAR_ON_DESELECT);
        baPubKeyV = JCSystem.makeTransientByteArray((short) FIELD_SIZE, JCSystem.CLEAR_ON_DESELECT);
        sessionKey = JCSystem.makeTransientByteArray((short) FIELD_SIZE, JCSystem.CLEAR_ON_DESELECT);

        // Store only the hash of the PIN.
        pinHash = new byte[HASH_SIZE];
        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hash.doFinal(buffer, offset, PIN_LENGTH, pinHash, (short)0);

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
        Util.arrayFillNonAtomic(baTempW, (short)0, (short)baTempW.length, (byte)0);
        Util.arrayFillNonAtomic(hostW, (short)0, (short)hostW.length, (byte)0);
        Util.arrayFillNonAtomic(g, (short)0, (short)g.length, (byte)0);

        Util.arrayFillNonAtomic(baPrivKeyU, (short)0, (short)baPrivKeyU.length, (byte)0);
        Util.arrayFillNonAtomic(baPubKeyU, (short)0, (short)baPubKeyU.length, (byte)0);
        Util.arrayFillNonAtomic(baPubKeyV, (short)0, (short)baPubKeyV.length, (byte)0);
        Util.arrayFillNonAtomic(sessionKey, (short)0, (short)sessionKey.length, (byte)0);
    }

    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card upon deselecting the applet. This also clear any sensitive
     * data that might remain in the memory.
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
        if (selectingApplet())
            return;

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != CLA_PV204APPLET)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (buffer[ISO7816.OFFSET_INS])
        {
            // TODO: Check that we're in the correct state.
            // Otherwise throw SW_COMMAND_NOT_ALLOWED
            case (byte) 0xD1:
                if (currentState != READY)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                establishSessionKey(apdu);
                break;
            case (byte) 0xD2:
                if (currentState != SESSION_KEY_ESTABLISHED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                process2(apdu);
                break;
            case (byte) 0xD3:
                if (currentState != KEY_CONFIRMED)
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                process3(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Receive EC public key from the host and send our own.
     * @param apdu The incoming APDU.
     */
    private void establishSessionKey(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short length = apdu.setIncomingAndReceive();

        // Validate buffer length. It must be exactly the size of a point on the elliptic curve.
        if (length < 49 || length > 50) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Store the host public key.
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, hostW, (short)0, length);

        // Generate a fresh key pair for ECDH.
        kpU = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        kpU.genKeyPair();
        privKeyU = (ECPrivateKey)kpU.getPrivate();
        pubKeyU = (ECPublicKey)kpU.getPublic();

        // Copy our public key into the APDU buffer and send it back.
        short lenW = pubKeyU.getW(baTempW, (short)0);
        Util.arrayCopyNonAtomic(baTempW, (short)0, buffer, ISO7816.OFFSET_CDATA, lenW);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, lenW);

        // Establish session key via ECDH.
        KeyAgreement ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ecdh.init(privKeyU);
        lenSessionKey = ecdh.generateSecret(hostW, (short)0, length,
                sessionKey, (short)0);

        currentState = SESSION_KEY_ESTABLISHED;
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
}
