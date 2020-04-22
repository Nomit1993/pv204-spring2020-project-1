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
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import java.math.BigInteger;
import java.util.Random;
import host.CardMngr;

public class SimpleAPDU 
{
    static CardMngr cardManager = new CardMngr();
    
    static String pin;
    static String pinset;
    static byte[] pinhash = new byte[20];
    
    static KeyPair kpV;
    static ECPrivateKey privKeyV;
    static ECPublicKey pubKeyV;

    static short lenA, lenB, lenP, lenPubK, lenPvtK, lenSS;

    static byte[] baTempA = new byte[25];
    static byte[] baTempB = new byte[25];
    static byte[] baTempP = new byte[25];
    static byte[] baTempW = new byte[50];
    static byte[] baTempS = new byte[25];
    static byte[] receivedACard = new byte[25];
    static byte[] k = new byte[25];
    
    private static final byte APPLET_AID[] = {
        (byte)0xEB, (byte)0x2C, (byte)0x23, (byte)0x1C,
        (byte)0xFD, (byte)0x22, (byte)0x1E, (byte)0x00
    };
	
    public static void main(String[] args) throws Exception 
    {
        byte[] installData = new byte[10];
        cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            
        String data = javax.xml.bind.DatatypeConverter.printHexBinary(APPLET_AID);
        System.out.print("Applet ID (AID): ");
        System.out.println(CardMngr.bytesToHex(APPLET_AID));
        System.out.println();

        pin();
    }    
    
    public static void pin() throws IOException, Exception
    {
	// Here, we set up (install) the applet inside the simulator.
        // Ask the user/vendor to configure the PIN for this specific card.
 	int attempts = 0;
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        
        while(attempts != 4)
        {
            System.out.print("Setting PIN (for CARD): ");
            pinset = br.readLine();

            if(!pin.matches("^[0-9]{4}$"))
            {
                System.out.println("Invalid PIN. Exactly Four Digits Required.");
                attempts++;
            }
            
            else
            {
                attempts = 4;
		System.out.println("PIN (HOST): " + pin);
                MessageDigest phash = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
                phash.doFinal(pin.getBytes(), (short)0, (short)pin.getBytes().length, pinhash,(short)0);
                System.out.print("Hash Of PIN (HOST): ");
                for (byte b: pinhash) System.out.print(String.format("%X",b));
                System.out.println();
        
		// Install and start up the applet with the specified PIN.
		// MATEJ Kindly check here
        	//cardManager.prepareLocalSimulatorApplet(APPLET_AID, pin.getBytes(), PV204Applet.class);
		    
		ecdhchannel();
            }
        }
    }
     
    public static void ecdhchannel() throws Exception
    {
        kpV = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_128);
        kpV.genKeyPair();
        privKeyV = (ECPrivateKey) kpV.getPrivate();
        pubKeyV = (ECPublicKey) kpV.getPublic();
        
        lenA = pubKeyV.getA(baTempA,(short)0); 
        lenB = pubKeyV.getB(baTempB,(short)0); 
        lenP = pubKeyV.getField(baTempP, (short)0); 
        lenPubK = pubKeyV.getW(baTempW,(short)0); 
        lenPvtK = privKeyV.getS(baTempS,(short)0); 
        
        System.out.print("Sending Parameter B (to CARD)");
        System.out.println();System.out.println("********************Trace [1]********************");
        byte sentB[] = new byte[CardMngr.HEADER_LENGTH + lenB];
        sentB[CardMngr.OFFSET_CLA] = (byte) 0xC1;
        sentB[CardMngr.OFFSET_INS] = (byte) 0xD1;
        sentB[CardMngr.OFFSET_P1] = (byte) 0x00;
        sentB[CardMngr.OFFSET_P2] = (byte) 0x00;
        sentB[CardMngr.OFFSET_LC] = (byte) 0x00;
        System.arraycopy(baTempB, 0, sentB, 5, lenB);
        byte[] receivedA = cardManager.sendAPDUSimulator(sentB);
        receivedACard = Arrays.copyOfRange(receivedA, 0, lenA);
        
        sharedsecret();
    }
    
    public static void sharedsecret() throws Exception
    {
        //HOST --> K = ((G ^ A) ^ B) mod P <--> (G ^ AB) mod P
        
        BigInteger A = bytetobiginteger(receivedACard);
        BigInteger B = bytetobiginteger(baTempB);
        BigInteger P = bytetobiginteger(baTempP);
        BigInteger G = bytetobiginteger(pinhash).mod(P);
        BigInteger K = G.modPow(A.multiply(B), P);
        
        k = bigintegertobyte(K, 16);
        System.out.println();
        System.out.print("Shared Secret K (HOST): ");
        for (byte b: k) System.out.print(String.format("%02X", b));
        
       System.out.println();System.out.println("********************Trace [3] ********************");
        
        byte receiveKCard[] = new byte[CardMngr.HEADER_LENGTH];
        receiveKCard[CardMngr.OFFSET_CLA] = (byte) 0xC1;
        receiveKCard[CardMngr.OFFSET_INS] = (byte) 0xD2;
        receiveKCard[CardMngr.OFFSET_P1] = (byte) 0x00;
        receiveKCard[CardMngr.OFFSET_P2] = (byte) 0x00;
        receiveKCard[CardMngr.OFFSET_LC] = (byte) 0x00;
        byte[] receivedK = cardManager.sendAPDUSimulator(receiveKCard);
        byte[] receivedKCard = Arrays.copyOfRange(receivedK, 0, k.length);
        
        System.out.println();
        System.out.println("Shared Key Equal (HOST and CARD): " + Arrays.equals(k, receivedKCard));
        
        aescommunication();
    }

    public static void aescommunication() throws Exception
    {
        int trace = 5;
        AESKey aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        while(trace!=11)
        {
            byte[] input = new byte[16];
            new Random().nextBytes(input);
            byte[] encinput = new byte[16];
            byte[] decinput = new byte[16];

            System.out.println();
            System.out.print("Input (HOST): ");
            for (byte b: input) System.out.print(String.format("%02X", b));
            System.out.println();
            
            aesKeyTrial.setKey(k,(short)0);
            aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT);
            aesCipher.doFinal(input, (short)0, (short)input.length, encinput, (short)0); 
            
            System.out.print("Encrypted Input (HOST): ");
            for (byte b: encinput) System.out.print(String.format("%02X", b));
            
            System.out.println();
            System.out.print("Sending Encrypted Input (to CARD)");
            System.out.println();System.out.println("********************Trace [" + trace + "]********************");
            
            byte sentencinput[] = new byte[CardMngr.HEADER_LENGTH + encinput.length];
            sentencinput[CardMngr.OFFSET_CLA] = (byte) 0x00;
            sentencinput[CardMngr.OFFSET_INS] = (byte) 0xD3;
            sentencinput[CardMngr.OFFSET_P1] = (byte) 0x00;
            sentencinput[CardMngr.OFFSET_P2] = (byte) 0x00;
            sentencinput[CardMngr.OFFSET_LC] = (byte) 0x00;
            System.arraycopy(encinput, 0, sentencinput, 5, encinput.length);
            byte[] receivedinput = cardManager.sendAPDUSimulator(sentencinput);
            byte[] receivedinputCard = Arrays.copyOfRange(receivedinput, 0, input.length);
            
            System.out.println();
            System.out.print("Encrypted Input (from CARD): ");
            for (byte b: receivedinputCard) System.out.print(String.format("%02X", b));
            System.out.println();
        
            aesKeyTrial.setKey(k,(short)0);
            aesCipher.init(aesKeyTrial, Cipher.MODE_DECRYPT);
            aesCipher.doFinal(receivedinputCard, (short)0, (short)decinput.length, decinput, (short)0);
            
            System.out.print("Decrypted Input (from CARD): ");
            for (byte b: decinput) System.out.print(String.format("%02X", b));
            System.out.println();
            
            trace = trace + 2;
        }
    }
    
    //For sharedsecret Function [https://github.com/chetan51/ABBC/blob/master/src/main/java/RSAEngine/Crypter.java]
    public static BigInteger bytetobiginteger(byte[]X)
    {
        BigInteger out = new BigInteger("0");
        BigInteger twofiftysix = new BigInteger("256");
        for(int i = 1; i <= X.length; i++)
            out = out.add((BigInteger.valueOf(0xFF & X[i - 1])).multiply(twofiftysix.pow(X.length-i)));
	return out;
    }

    public static byte[] bigintegertobyte(BigInteger X, int XLen)
    {
        BigInteger twofiftysix = new BigInteger("256");
	byte[] out = new byte[XLen];
        BigInteger[] cur;
        if(X.compareTo(twofiftysix.pow(XLen)) >= 0)
		return new String("integer too large").getBytes();		
	for(int i = 1; i <= XLen; i++)
        {
            cur = X.divideAndRemainder(twofiftysix.pow(XLen-i));
            out[i - 1] = cur[0].byteValue();
        }
        return out;
    }
}
