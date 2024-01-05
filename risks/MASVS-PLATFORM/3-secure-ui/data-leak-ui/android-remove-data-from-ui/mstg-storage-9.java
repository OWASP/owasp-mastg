public class MainActivity extends AppCompatActivity {
     private void test(){
          getWindow().setFlags(8192, 8192);
     }
     private void test2(){
          Window window = activity.getWindow();
          window.setFlags(8192, 8192);
          // ruleid: MSTG-STORAGE-9
          window.setFlags(1024, 1024);
     }
}
// ruleid: MSTG-STORAGE-9
public class MainActivity2 extends AppCompatActivity {
     private void test(){
          //getWindow().addFlags(8192);
     }
}
// ok: MSTG-STORAGE-9
public class MainActivity3 extends AppCompatActivity {
     private void test(){
          // ruleid: MSTG-STORAGE-9
          getWindow().addFlags(222);
     }
}
