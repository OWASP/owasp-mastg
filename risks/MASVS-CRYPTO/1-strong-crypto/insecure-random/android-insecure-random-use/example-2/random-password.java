import java.util.Random;

public class InsecurePasswordGenerator {
    public static void main(String[] args) {
        String password = generatePassword(10); // Example length of 10 characters
        System.out.println("Generated Password: " + password);
    }

    private static String generatePassword(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }

        return password.toString();
    }
}
