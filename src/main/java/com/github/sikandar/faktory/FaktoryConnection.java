package com.github.sikandar.faktory;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * This class is used to handle connections with Faktory.
 * It connects into Faktory using a Socket.
 * <p>
 * property uri the URI from the Faktory Server.
 *
 * @author Sikandar Ali Awan
 */
public class FaktoryConnection {

    private static final Pattern HI_RECEIVED = Pattern.compile("\\+HI\\s\\{\"v\":\\d}");
    private static final Pattern OK_RECEIVED = Pattern.compile("\\+OK");
    private static final String HELLO_WITH_NO_PASSWORD = "HELLO {\"v\":2}";
    private static final String HELLO_WITH_PASSWORD = "HELLO {\"pwdhash\":\"%s\",\"v\":2}";

    private final URI url;
    private final String password;
    private Socket socket;
    private BufferedReader fromServer;
    private DataOutputStream toServer;

    public FaktoryConnection(String url) {
        this.url = URI.create(url);
        this.password = null;
    }

    public FaktoryConnection(String url, String password) {
        this.url = URI.create(url);
        this.password = password;
    }

    /**
     * Method used to connect to Faktory using a Socket.
     */
    public void connect() throws IOException {
        socket = openSocket();
        toServer = new DataOutputStream(socket.getOutputStream());
        fromServer = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        send(getHelloMessage(readFromSocket()));
    }

    public void send(String message) throws IOException {
        if (socket == null)
            throw new FaktoryException("Socket not initialized");

        writeToSocket(message);
        String response = readFromSocket();
        if (!OK_RECEIVED.matcher(response).matches()) {
            throw new FaktoryException("Invalid +OK, Expecting:" + OK_RECEIVED);
        }
    }

    public void close() throws IOException {
        socket.close();
    }

    private Socket openSocket() throws IOException {
        return new Socket(url.getHost(), url.getPort());
    }

    private String readFromSocket() throws IOException {
        return fromServer.readLine();
    }

    private void writeToSocket(String content) throws IOException {
        toServer.writeBytes(content + "\n");
    }

    private String getHelloMessage(String hiMessage) throws IOException {
        // If password not set in faktory you will receive "+HI {"v":2}"
        if (password == null || password.length() == 0) {
            if (!HI_RECEIVED.matcher(hiMessage).matches()) {
                throw new FaktoryException("Invalid +HI, Expecting:" + HI_RECEIVED);
            }
            return HELLO_WITH_NO_PASSWORD;
        }

        // If password set in faktory you will receive payload like
        // "+HI {"v":2,"i":5171,"s":"5fb7c632793578c7"}"
        // Parse the message to find version, salt and number of iteration
        String jsonPayload = hiMessage.substring(hiMessage.indexOf('{'));
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> hiMap = objectMapper.readValue(jsonPayload, Map.class);
        String salt = (String) hiMap.get("s");
        Integer iterations = (Integer) hiMap.get("i");

        if (salt == null || iterations == null) {
            throw new FaktoryException("Salt/Iterations cannot be null if password is set.");
        }

        return String.format(HELLO_WITH_PASSWORD, hashPassword(password, salt, iterations));
    }

    private String hashPassword(String password, String salt, int iterations) {
        try {
            // Combine password and salt
            String input = password + salt;
            byte[] bytes = input.getBytes("UTF-8");

            // Initialize SHA-256 MessageDigest
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);

            // Perform multiple iterations
            for (int i = 1; i < iterations; i++) {
                hash = digest.digest(hash);
            }

            // Convert byte array to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException("Error while hashing password", e);
        }
    }
}
