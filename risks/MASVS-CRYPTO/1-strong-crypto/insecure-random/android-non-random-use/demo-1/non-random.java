// SUMMARY: This sample demonstrates different ways of creating non-random tokens in Java.

public class A{

    private int gen_token(){
        // FAIL: [android-insecure-random-use] The app uses Date().getTime() for generating authentication tokens.
        return abc(new Date().getTime());
    }
    private int gen_token(){
        Calendar c = Calendar.getInstance();
        // FAIL: [android-insecure-random-use] The app uses Calendar.getInstance().getTimeInMillis() for generating authentication tokens.
        int mseconds = c.get(Calendar.MILLISECOND)
    }
}
