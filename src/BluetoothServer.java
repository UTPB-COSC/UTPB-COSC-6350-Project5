import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class BluetoothServer {
    static byte [] serverECDHPublicKey = new byte[91];
    static byte [] serverECDHPrivateKey = new byte[67];
    static byte [] clientECDHPublicKey = new byte[91];
    static PrivateKey RSAprivateKey;
    static byte [] sharedSessionKey = new byte [32];

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(9999);
            System.out.println("Server listening on port " + 9999);

            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected.");

            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());

            //Sends message one to client
            messageOne(out);

            //Receives message two from the client
            receiveMessageTwo(in);
            //Generates EC keys for the server
            serverECDHGenerator();

            //Sends message three to client
            messageThree(out);
            sharedSessionKey = keyAgreement();

            //tests packet encryption using the shared session key
            String clientMessage = receiveDecryptedMessage(in);
            System.out.println("Client said: " + clientMessage);
            sendEncryptedMessage(out, "Hello, Client!");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //Generates the RSA public key that will be sent to the client
    public static byte[] generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = serverKeyPair.getPublic();
        RSAprivateKey = serverKeyPair.getPrivate();
        return publicKey.getEncoded();
    }

    public static void messageOne(DataOutputStream out) throws NoSuchAlgorithmException, IOException {
        out.write(generateKeys());
    }

    public static void messageThree(DataOutputStream out) throws IOException {
        out.write(serverECDHPublicKey);
    }

    public static void receiveMessageTwo(DataInputStream in) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        int length = in.readInt();
        byte[] clientContribution = new byte[length];
        in.readFully(clientContribution);
        decryptClientContribution(clientContribution);
    }

    //decrypts the client contribution (server RSA public that was encrypted with the clients EC public) this is used to get the clients pubic key
    public static void decryptClientContribution(byte [] clientContribution) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        // Initialize the cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, RSAprivateKey);

        // Decrypt the client contribution
        clientECDHPublicKey = cipher.doFinal(clientContribution);
    }

    //generates ec keys for the server
    public static void serverECDHGenerator() throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = serverKeyPair.getPublic();
        PrivateKey privateKey = serverKeyPair.getPrivate();

        serverECDHPublicKey = publicKey.getEncoded();
        serverECDHPrivateKey = privateKey.getEncoded();
    }

    //Generates the shared session key
    public static byte [] keyAgreement() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey serverPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(serverECDHPrivateKey));
        PublicKey clientPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientECDHPublicKey));

        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");

        keyAgree.init(serverPrivateKey);
        keyAgree.doPhase(clientPublicKey, true);
        return keyAgree.generateSecret();
    }

    //tests packet encryption functionality
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



