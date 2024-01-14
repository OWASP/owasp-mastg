// SUMMARY: This sample demonstrates different common ways of insecurely generating random numbers in Java.

import java.util.Random;
import java.lang.*;
import java.security.SecureRandom;

public class A{
    String a = "test";
    private int test(){
        return 1 + new Random().nextInt(6);
    }
    private int test2random(){
        // ruleid: MSTG-CRYPTO-6
        return 1 + Math.random();
    }
    private int test3gen(){
        Random r = new Random();
        // ruleid: MSTG-CRYPTO-6
        return r.nextDouble();
    }
    private int test4(){
        // ruleid: MSTG-CRYPTO-6
        SecureRandom number = new SecureRandom(12);
        return number.nextInt(21);
    }
    //This case is not cover
    private int random(){
        int b = 3;
        return b + 10;
    }
    private int random(){
        SecureRandom number = new SecureRandom();
        // ok: MSTG-CRYPTO-6
        return number.nextInt(21);
    }
    private int gen_token(){
        // ruleid: MSTG-CRYPTO-6
        return abc(new Date().getTime());
    }
    private int gen_token(){
        Calendar c = Calendar.getInstance();
        // ruleid: MSTG-CRYPTO-6
        int mseconds = c.get(Calendar.MILLISECOND)
    }
}
