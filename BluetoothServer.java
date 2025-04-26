import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class BluetoothServer {
    private static final int PORT = 12345;

    public static void main(String[] args) throws Exception {
        // Port the connection will be established on
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server started, waiting for client connection...");

        // Accept waits for client request
        Socket socket = serverSocket.accept();
        System.out.println("Client connected!");

        // Step 1: Generate server's ECDH key pair
        KeyPair serverKeyPair = generateECDHKeyPair();
        PublicKey serverPublicKey = serverKeyPair.getPublic();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        System.out.println("Server's Public Key: " + serverPublicKey);

        // Step 2: Exchange public keys with the client
        sendPublicKey(socket, serverPublicKey);
        System.out.println("Sent server's public key to the client.");

        PublicKey clientPublicKey = receivePublicKey(socket);
        System.out.println("Received client's public key: " + clientPublicKey);

        // Step 3: Derive the shared session key
        byte[] sharedSecret = generateSharedSecret(serverPrivateKey, clientPublicKey);
        byte[] sessionKey = deriveSessionKey(sharedSecret);
        
        System.out.println("Session key established and derived from shared secret.");

        // Step 4: Send and receive multiple packets
        for (int i = 0; i < 5; i++) {  // Example: send and receive 5 packets
            // Send an encrypted packet to the client
            String message = "Packet " + (i + 1) + " from server!";
            // TODO: Add messages that server can send 
            Packet packet = createEncryptedPacket(message.getBytes(), sessionKey);
            System.out.println("Sending encrypted packet...");
            sendPacket(socket, packet);

            // Step 5: Receive and decrypt a packet from the client
            Packet receivedPacket = receivePacket(socket);
            byte[] decryptedPayload = decryptPayload(receivedPacket, sessionKey);
            System.out.println("Decrypted message from client: " + new String(decryptedPayload));
        }

        socket.close();
        serverSocket.close();
    }

    // Helper methods for key exchange, session key derivation, encryption, and decryption

    private static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
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
        return Arrays.copyOf(sha256.digest(sharedSecret), 16); // Use the first 16 bytes
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
        byte[] nonce = new byte[12];
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
    public byte[] header;  // Nonce or metadata
    public byte[] payload; // Encrypted payload
    public byte[] authTag; // Authentication tag

    public Packet(byte[] header, byte[] payload, byte[] authTag) {
        this.header = header;
        this.payload = payload;
        this.authTag = authTag;
    }
}
