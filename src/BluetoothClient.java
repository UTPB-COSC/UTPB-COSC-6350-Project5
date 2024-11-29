import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.spec.*;

public class BluetoothClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;
    private static SecretKey sharedKey;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, PORT)) {
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Step 1: Generate client's key pair (ECDHE)
            KeyPair clientKeyPair = generateKeyPair();
            byte[] clientPublicKeyEncoded = clientKeyPair.getPublic().getEncoded();
            output.writeInt(clientPublicKeyEncoded.length);
            output.write(clientPublicKeyEncoded);
            System.out.println("Client Public Key (hex): " + bytesToHex(clientPublicKeyEncoded));

            // Step 2: Receive server's public key
            int serverPublicKeyLength = input.readInt();
            byte[] serverPublicKeyEncoded = new byte[serverPublicKeyLength];
            input.readFully(serverPublicKeyEncoded);
            System.out.println("Server Public Key (hex): " + bytesToHex(serverPublicKeyEncoded));

            PublicKey serverPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(serverPublicKeyEncoded));

            // Step 3: Derive shared secret using ECDHE
            sharedKey = generateSharedSecret(clientKeyPair.getPrivate(), serverPublicKey);
            System.out.println("Shared Key (hex): " + bytesToHex(sharedKey.getEncoded()));

            // Step 4: Receive encrypted confirmation message
            int confirmationLength = input.readInt();
            byte[] encryptedConfirmation = new byte[confirmationLength];
            input.readFully(encryptedConfirmation);
            System.out.println("Encrypted Confirmation (hex): " + bytesToHex(encryptedConfirmation));

            // Step 5: Send acknowledgment to the server
            String acknowledgment = "Acknowledged";
            output.write(acknowledgment.getBytes());
            System.out.println("Client acknowledgment sent.");

            // Step 6: Receive encrypted message from the server
            int messageLength = input.readInt();
            byte[] encryptedMessage = new byte[messageLength];
            input.readFully(encryptedMessage);
            System.out.println("Encrypted Message (hex): " + bytesToHex(encryptedMessage));

            byte[] iv = new byte[16];
            System.arraycopy(encryptedMessage, 0, iv, 0, iv.length);
            byte[] encryptedData = new byte[encryptedMessage.length - iv.length];
            System.arraycopy(encryptedMessage, iv.length, encryptedData, 0, encryptedData.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sharedKey, ivSpec);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            System.out.println("Decrypted Message: " + new String(decryptedData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
