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
package host;

import applets.PV204Applet;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import java.math.BigInteger;

public class HostClientApp
{
    final static short FIELD_SIZE = KeyBuilder.LENGTH_EC_FP_192;
    final static short HASH_SIZE = 32;

    static CardMngr cardManager = new CardMngr();

    //ECDH Parameters
    static byte[] g = new byte[FIELD_SIZE];
    static byte[] trace1 = new byte[FIELD_SIZE];
    static KeyPair kpV;
    static ECPrivateKey privKeyV;
    static ECPublicKey pubKeyV;
    static KeyAgreement ecdhV;
    private static byte baPrivKeyV[] = new byte[FIELD_SIZE];
    private static byte baPubKeyV[] = new byte[FIELD_SIZE];
    private static byte baPubKeyU[] = new byte[FIELD_SIZE];
    private static byte[] pinHash = new byte[HASH_SIZE];
    private static byte[] sessionKey = new byte[FIELD_SIZE];
    private static short lenSessionKey = 0;

    private static final byte APPLET_AID[] = {
        (byte)0xEB, (byte)0x2C, (byte)0x23, (byte)0x1C,
        (byte)0xFD, (byte)0x22, (byte)0x1E, (byte)0x00
    };

    public static void main(String[] args) throws Exception
    {
        System.out.println(String.format("Applet ID (AID): %s", CardMngr.bytesToHex(APPLET_AID)));

        // Here, we set up (install) the applet inside the simulator.
        // Ask the user/vendor to configure the PIN for this specific card.
        System.out.print("Set up PIN for card: ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String pin = br.readLine();

        // Validate PIN format.
        if(!pin.matches("^[0-9]{4}$")) {
            System.out.println("Invalid PIN. Exactly four digits required.");
            System.exit(1);
        }

        // Install and start up the applet with the specified PIN.
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, pin.getBytes(), PV204Applet.class);

        System.out.println("*** Host application ***");

        // Ask the user for PIN and store its hash.
        askForPIN();
        // Start the protocol now.
        establishSessionKey();
        //aes();
    }

    /**
     * Ask the user for the applet's PIN.
     * @throws Exception
     */
    private static void askForPIN() throws Exception
    {
        // Ask the user to enter the preconfigured PIN.
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter PIN (PC): ");
        String pin = br.readLine();

        // Validate PIN format.
        if(!pin.matches("^[0-9]{4}$"))
        {
            System.out.println("Invalid PIN. Exactly four digits required.");
            System.exit(1);
        }

        // Compute and store the hash of the PIN.
        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hash.doFinal(pin.getBytes(), (short)0, (short)pin.getBytes().length, pinHash, (short)0);
    }

    /**
     * First phase of the protocol -- establish a common session key between the host and
     * the applet.
     * @throws Exception
     */
    private static void establishSessionKey() throws Exception
    {
        // Generate a 192-bit EC key pair.
        KeyPair pair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        pair.genKeyPair();
        ECPrivateKey ecPrivate = (ECPrivateKey)pair.getPrivate();
        ECPublicKey ecPublic = (ECPublicKey)pair.getPublic();

        byte[] pub_w = new byte[2*FIELD_SIZE];

        short lenW = ecPublic.getW(pub_w, (short)0);

        byte apdu[];

        // First message in the sequence:
        // Host --> Applet: public key W
        apdu = new byte[CardMngr.HEADER_LENGTH + lenW];
        apdu[CardMngr.OFFSET_CLA] = (byte)0xC1;
        apdu[CardMngr.OFFSET_INS] = (byte)0xD1;
        apdu[CardMngr.OFFSET_P1] = (byte)0x00;
        apdu[CardMngr.OFFSET_P2] = (byte)0x00;
        apdu[CardMngr.OFFSET_LC] = (byte)lenW;
        System.arraycopy(pub_w, 0, apdu, CardMngr.HEADER_LENGTH, lenW);

        // Send the message, receive and parse response.
        byte[] response = cardManager.sendAPDUSimulator(apdu);
        short lenAppletPublic = (short)(response.length - 2); // Cut off the 0x9000 OK response.
        // TODO: Check that the public key is valid and has the correct size.
        byte[] appletPublic = Arrays.copyOfRange(response, 0, lenAppletPublic);

        KeyAgreement ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ecdh.init(ecPrivate);
        lenSessionKey = ecdh.generateSecret(appletPublic, (short)0, lenAppletPublic,
                sessionKey, (short)0);
    }

    private static void aes() throws Exception
    {
        AESKey aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        byte[] input = {(byte)0x44,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,0x10,(byte)0xA2, 0x35, (byte)0x5E,0x15,0x16,0x14};
        byte[] output = new byte[16];
        short len = (short) input.length;

        System.out.print("Input (V): ");
        for (byte b: input) System.out.print(String.format("%02X", b));
        System.out.println();

        aesKeyTrial.setKey(g,(short)0);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(input, (short)0, len, output, (short)0);
        System.out.print("Encrypted Input (V): ");
        for (byte b: output) System.out.print(String.format("%02X", b));
        System.out.println();

        byte ss2[] = new byte[CardMngr.HEADER_LENGTH + output.length];
        ss2[CardMngr.OFFSET_CLA] = (byte) 0xC1;
        ss2[CardMngr.OFFSET_INS] = (byte) 0xD3;
        ss2[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss2[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss2[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(output, 0, ss2, CardMngr.HEADER_LENGTH, output.length);
        byte[] sss2 = cardManager.sendAPDUSimulator(ss2);
        trace1 = Arrays.copyOfRange(sss2, 0, FIELD_SIZE);
        System.out.println();
        System.out.print("Received Encrypted Input from Card (V) " + trace1.length + " :");
        for (byte b: trace1) System.out.print(String.format("%02X", b));
        System.out.println();

        byte[] input1 = new byte[16];
        aesKeyTrial.setKey(g,(short)0);
        aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(trace1, (short)0, len, input1, (short)0);
        System.out.print("Decrypted Input from Card (V): ");
        for (byte b: input1) System.out.print(String.format("%02X", b));
        System.out.println();
    }
}
