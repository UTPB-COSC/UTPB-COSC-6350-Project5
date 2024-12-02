import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class BluetoothClient {
    static byte [] serverRSAPublicKey = new byte[294];
    static byte [] clientECDHPublicKey = new byte[91];
    static byte [] clientECDHPrivateKey = new byte[67];
    static byte [] serverECDHPublicKey = new byte[91];
    static byte [] sharedSessionKey = new byte [32];

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 9999);
            System.out.println("Connected to server.");

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            //receives message one from the server
            receiveMessageOne(in);

            //Generates and stores ECDH keys
            clientECDHGenerator();

            //Sends contents of message two to server
            messageTwo(out);

            //receives message three from client
            receiveMessageThree(in);
            sharedSessionKey = keyAgreement();

            //Tests encryption of packets using shared session key
            sendEncryptedMessage(out, "Hello, Server!");
            String serverReply = receiveDecryptedMessage(in);
            System.out.println("Server replied: " + serverReply);

        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void receiveMessageOne(DataInputStream in) throws IOException {
        in.readFully(serverRSAPublicKey);
    }

    public static void receiveMessageThree(DataInputStream in) throws IOException {
        in.readFully(serverECDHPublicKey);
    }

    public static void messageTwo(DataOutputStream out) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        byte [] clientContribution = encryptServerRSAPublicKey();
        out.writeInt(clientContribution.length);
        out.write(clientContribution);
    }

    //Generates ECDH client keys
    public static void clientECDHGenerator() throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair clientKeyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = clientKeyPair.getPublic();
        PrivateKey privateKey = clientKeyPair.getPrivate();

        clientECDHPublicKey = publicKey.getEncoded();
        clientECDHPrivateKey = privateKey.getEncoded();
    }

    //Encrypts the public key sent by the server using the clients public key
    public static byte [] encryptServerRSAPublicKey() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverRSAPublicKey);
        PublicKey severRSAPub = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, severRSAPub);
        return cipher.doFinal(clientECDHPublicKey);
    }

    //Performs a key agreement to be used as the shared session key
    private static byte [] keyAgreement() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey clientPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(clientECDHPrivateKey));
        PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverECDHPublicKey));

        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");

        keyAgree.init(clientPrivateKey);
        keyAgree.doPhase(serverPublicKey, true);
        return keyAgree.generateSecret();
    }


    //encrypts and sends test packet to server
    public static void sendEncryptedMessage(DataOutputStream out, String message) throws Exception {
        // Encrypt the message using the shared session key
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(sharedSessionKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(message.getBytes());

        // Send the IV and ciphertext
        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(ciphertext.length);
        out.write(ciphertext);
    }

    //receives and decrypts test packet from server
    public static String receiveDecryptedMessage(DataInputStream in) throws Exception {
        // Read the IV
        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        // Read the ciphertext
        int ciphertextLength = in.readInt();
        byte[] ciphertext = new byte[ciphertextLength];
        in.readFully(ciphertext);

        // Decrypt the message using the shared session key
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(sharedSessionKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext);
    }


}
