public class A{
    private void encrypt(String a, String c){
        // ruleid: MSTG-CRYPTO-2
        byte three = one ^ two;
        // ruleid: MSTG-CRYPTO-2
        byte[] b = xorArrayBytes(operador1, operador2);
    }
    private void test(String a, String c){
        // ok: MSTG-CRYPTO-2
        byte three = one ^ two;
        // ok: MSTG-CRYPTO-2
        byte[] b = xorArrayBytes(operador1, operador2);
    }
}
