# Mifare DESFire - An Introduction

Taken from article https://www.linkedin.com/pulse/mifare-desfire-introduction-david-coelho by David Coelho

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.smartcardio.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;

public class Main {

    public static void main(String[] args) throws Exception {

        CardChannel channel = createCardChannel();
        try {

            ResponseAPDU response;

            /*
             * Sending the GetCardUID APDU: 9051000000
             * This command requires a previous authentication, as it is not authenticated at this point
             * the card shall return '0x91 0xae', which means Authentication Error.
             */
            response = channel.transmit(new CommandAPDU(new byte[]{(byte)0x90, 0x51, 0x00, 0x00, 0x00}));
            log("Response from GetCardUID without authentication (91ae):" + toHexString(response.getBytes()));

            /*
             * Sending the GetChallenge APDU: 901a0000010000
             * This is the starting point of the authentication.
             */
            response = channel.transmit(new CommandAPDU(new byte[]{(byte)0x90, 0x1a, 0x00, 0x00, 0x01, 0x00, 0x00}));
            log("Authentication challenge (8 bytes challenge + 91af) : " + toHexString(response.getBytes()));

            byte[] challenge = response.getData();

            // Of course rndA is expected to a random number. But for the tutorial we keep it as a constant.byte[] rndA = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

            // DESFire Default DES key is zero byte array.byte[] defaultDESKey = new byte[8];
            byte[] IV = new byte[8];

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            IV = challenge;
            log("Decrypted rndB: " + toHexString(rndB));

            // Rotate left the rndBbyte[] leftRotatedRndB = rotateLeft(rndB);
            log("Left rotated rndB: " + toHexString(leftRotatedRndB));

            // Concatenate the RndA and rotated RndBbyte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            log("rndA and rndB: " + toHexString(rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answerbyte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            log("Challenge answer: " + toHexString(challengeAnswer));
            IV = Arrays.copyOfRange(challengeAnswer, 8, 16);

            /*
              Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
              The total size of apdu (for this scenario) is 22 bytes:
              > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
            */byte[] challengeAnswerAPDU = new byte[22];
            challengeAnswerAPDU[0] = (byte)0x90; // CLS
            challengeAnswerAPDU[1] = (byte)0xAF; // INS
            challengeAnswerAPDU[2] = (byte)0x00; // p1
            challengeAnswerAPDU[3] = (byte)0x00; // p2
            challengeAnswerAPDU[4] = (byte)0x10; // data length: 16 bytes
            challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte)0x00;
            System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);
            log("Challenge Answer APDU: " + toHexString(challengeAnswerAPDU));

            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 10 bytes [rndA from the Card] + 9100
             */
            response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            log("Response for challenge answer (10 bytes expected): " + toHexString(response.getBytes()));

            /*
             * At this point, the challenge was processed by the card. The card decrypted the rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            log("Rotated rndA from Card: " + toHexString(rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);

            if (Arrays.equals(rndA, rndAFromCard)) {
                log("Authenticated!!!");
            } else {
                System.err.println(" ### Authentication failed. ### ");
                log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
            }

        } finally {
             channel.getCard().disconnect(false);
        }

    }

    private static CardChannel createCardChannel() throws CardException {

        log("Opening channel...");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        log("Terminals: " + terminals);

        CardTerminal terminal = terminals.get(0);

        Card card = terminal.connect("T=1");

        byte[] atr = card.getATR().getBytes();
        log("ATR: " + toHexString(atr));

        return card.getBasicChannel();
    }

    private static void log(String msg) {
        System.out.println(msg);
    }

    /***
     * Given a byte array, convert it to a hexadecimal representation.
     *
     * @param data: Byte Array
     * @return String containing the hexadecimal representation
     */private static String toHexString(byte[] data) {
        StringBuilder hexString = new StringBuilder();
        for (byte item : data) {
            String hex = String.format("%02x", item);
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static byte[] decrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static byte[] encrypt(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }


    private static Cipher getCipher(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);

        cipher.init(mode, keySpec, algorithmParamSpec);

        return cipher;
    }

    private static byte[] rotateLeft(byte[] data) {
        byte[] rotated = new byte[data.length];

        rotated[data.length - 1] = data[0];

        for (int i = 0; i < data.length - 1; i++) {
            rotated[i] = data[i + 1];
        }
        return rotated;
    }

    private static byte[] rotateRight(byte[] data) {
        byte[] unrotated = new byte[data.length];

        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }

        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    private static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];

        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }

        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }

        return concatenated;
    }

}
