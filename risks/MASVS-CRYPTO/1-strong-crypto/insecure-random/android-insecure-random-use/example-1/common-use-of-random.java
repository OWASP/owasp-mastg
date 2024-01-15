// SUMMARY: This sample demonstrates different common ways of insecurely generating random numbers in Java.

import java.util.Random;
import java.lang.*;
import java.security.SecureRandom;

public class CommonRandom {

    private int gen_token(){
        Random r = new Random();
        // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for generating authentication tokens.
        return r.nextDouble();
    }

    private int get_random(){
        // FAIL: [android-insecure-random-use] The title of the function indicates that it generates a random number, but it is unclear how it is actually used in the rest of the app. Review any calls to this function to ensure that the random number is not used in a security-relevant context.
        return 1 + Math.random();
    }

    private static String generatePassword(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            // FAIL: [android-insecure-random-use] The app insecurely uses random numbers for generating passwords, which is a secuity-relevant context.
            password.append(characters.charAt(random.nextInt(characters.length())));
        }

        return password.toString();
    }

    private int random(){
        SecureRandom number = new SecureRandom();
        // PASS: [android-insecure-random-use] The app uses a secure random number generator.
        return number.nextInt(21);
    }

}
