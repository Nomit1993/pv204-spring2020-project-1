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
    static CardMngr cardManager = new CardMngr();

    //ECDH Parameters
    static byte[] baTempA = new byte[17];
    static byte[] baTempB = new byte[17];
    static byte[] baTempP = new byte[17];
    static byte[] baTempW = new byte[33];
    static byte[] baTempS = new byte[17];
    static byte[] baTempSS = new byte[17];
    static byte[] baTempSS1 = new byte[17];
    static byte[] g = new byte[17];
    static byte[] trace1 = new byte[17];
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

    private static final byte APPLET_AID[] = {
        (byte)0xEB, (byte)0x2C, (byte)0x23, (byte)0x1C,
        (byte)0xFD, (byte)0x22, (byte)0x1E, (byte)0x00
    };

    public static void main(String[] args) throws Exception
    {
        // TODO: Pass the PIN here.
        byte[] installData = new byte[10];
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, PV204Applet.class);

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

        byte pu[] = new byte[CardMngr.HEADER_LENGTH + lenB];
        pu[CardMngr.OFFSET_CLA] = (byte) 0x00;
        pu[CardMngr.OFFSET_INS] = (byte) 0xD1;
        pu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pu[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(baTempB, 0, pu, 5, lenB);
        byte[] pus = cardManager.sendAPDUSimulator(pu);
        baPubKeyU = Arrays.copyOfRange(pus, 0, 17);
        System.out.println();
        System.out.print("A Parameter Received from Card (U) " + baPubKeyU.length + " :");
        for (byte b: baPubKeyU) System.out.print(String.format("%02X", b));
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

        System.out.print("G (V): ");
        for (byte b: g) System.out.print(String.format("%02X", b));
        System.out.println();

        /*BigInteger a1 = btbi(baPubKeyU);
          Random rand = new Random();
          int a = rand.nextInt(1);
        //System.out.println(a.intValue());
        BigInteger midv = btbi(g).pow(a).mod(p);
        byte[] midV = bitb(midv, 16);

        BigInteger bb = btbi(baTempB);
        BigInteger k1 = btbi(midV).pow(bb.intValue()).mod(p);
        byte[] k = bitb(k1, 16);

        System.out.print("Shared Secret At PC (V) " + k.length + " :");
        for (byte b: k) System.out.print(String.format("%02X", b));
        System.out.println();*/

        byte ss[] = new byte[CardMngr.HEADER_LENGTH + lenW];
        ss[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss[CardMngr.OFFSET_INS] = (byte) 0xD2;
        ss[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(baTempB, 0, ss, 5, lenB);
        byte[] sss = cardManager.sendAPDUSimulator(ss);
        baTempSS1 = Arrays.copyOfRange(sss, 0, 16);
        System.out.println();
        System.out.print("G from Card (U) :");
        for (byte b: baTempSS1) System.out.print(String.format("%02X", b));
        System.out.println();

        System.out.println("Shared G Equal: " + Arrays.equals(g, baTempSS1));

        aes();
    }

    public static void aes() throws Exception
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
        ss2[CardMngr.OFFSET_CLA] = (byte) 0x00;
        ss2[CardMngr.OFFSET_INS] = (byte) 0xD3;
        ss2[CardMngr.OFFSET_P1] = (byte) 0x00;
        ss2[CardMngr.OFFSET_P2] = (byte) 0x00;
        ss2[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(output, 0, ss2, 5, output.length);
        byte[] sss2 = cardManager.sendAPDUSimulator(ss2);
        trace1 = Arrays.copyOfRange(sss2, 0, 17);
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

    // helper functions for SPEKE calculations [IEE163] [https://github.com/chetan51/ABBC/blob/master/src/main/java/RSAEngine/Crypter.java]
    public static BigInteger btbi(byte[]X)
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


    public static byte[] bitb(BigInteger X, int XLen)
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
