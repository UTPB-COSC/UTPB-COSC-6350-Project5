import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class BluetoothClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket(SERVER_ADDRESS, PORT);
        System.out.println("Connected to server!");

        // Step 1: Generate client's ECDH key pair
        KeyPair clientKeyPair = generateECDHKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
        System.out.println("Client's Public Key: " + clientPublicKey);

        // Step 2: Exchange public keys with the server
        sendPublicKey(socket, clientPublicKey);
        System.out.println("Sent client's public key to the server.");

        PublicKey serverPublicKey = receivePublicKey(socket);
        System.out.println("Received server's public key: " + serverPublicKey);

        // Step 3: Derive the shared session key
        byte[] sharedSecret = generateSharedSecret(clientPrivateKey, serverPublicKey);
        byte[] sessionKey = deriveSessionKey(sharedSecret);
        
        System.out.println("Session key established and derived from shared secret.");

        // Step 4: Send and receive multiple packets
        for (int i = 0; i < 5; i++) {  // Example: send and receive 5 packets
            // Receive and decrypt a packet from the server
            Packet receivedPacket = receivePacket(socket);
            byte[] decryptedPayload = decryptPayload(receivedPacket, sessionKey);
            System.out.println("Decrypted message from server: " + new String(decryptedPayload));

            // Send an encrypted packet to the server
            String responseMessage = "Packet " + (i + 1) + " from client!";
            Packet responsePacket = createEncryptedPacket(responseMessage.getBytes(), sessionKey);
            System.out.println("Sending encrypted packet to the server...");
            sendPacket(socket, responsePacket);
        }

        socket.close();
    }

    // Helper methods for key exchange, session key derivation, encryption, and decryption

    private static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256); // 256-bit curve
        return keyPairGenerator.generateKeyPair();
    }

    private static void sendPublicKey(Socket socket, PublicKey publicKey) throws IOException {
        OutputStream out = socket.getOutputStream();
        out.write(publicKey.getEncoded());
        out.flush();
    }

    private static PublicKey receivePublicKey(Socket socket) throws Exception {
        InputStream in = socket.getInputStream();
        byte[] keyBytes = in.readNBytes(91); // Adjust size based on key length
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    private static byte[] deriveSessionKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return Arrays.copyOf(sha256.digest(sharedSecret), 16); // First 16 bytes
    }

    private static Packet createEncryptedPacket(byte[] payload, byte[] sessionKey) throws Exception {
        byte[] nonce = generateNonce();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), spec);

        byte[] encryptedPayload = cipher.doFinal(payload);
        byte[] authTag = Arrays.copyOfRange(encryptedPayload, encryptedPayload.length - 16, encryptedPayload.length);

        return new Packet(nonce, encryptedPayload, authTag);
    }

    private static byte[] decryptPayload(Packet packet, byte[] sessionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, packet.header);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), spec);

        return cipher.doFinal(packet.payload);
    }

    private static byte[] generateNonce() {
        byte[] nonce = new byte[12]; // 96-bit nonce
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static void sendPacket(Socket socket, Packet packet) throws IOException {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.writeObject(packet);
        out.flush();
    }

    private static Packet receivePacket(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        return (Packet) in.readObject();
    }
}

class Packet implements Serializable {
    byte[] header;
    byte[] payload;
    byte[] authTag;

    public Packet(byte[] header, byte[] payload, byte[] authTag) {
        this.header = header;
        this.payload = payload;
        this.authTag = authTag;
    }
}
