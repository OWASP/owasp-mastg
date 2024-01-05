public class BroadcastReceiverLeakActivity extends AppCompatActivity {

    private BroadcastReceiver broadcastReceiver;

    private void registerBroadCastReceiver() {
        broadcastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                //your receiver code goes here!
            }
        };
        // ruleid: MSTG-CODE-8.1
        registerReceiver(broadcastReceiver, new IntentFilter("SmsMessage.intent.MAIN"));
    }
    
    @Override
    protected void onStart() {
        super.onStart();
        registerBroadCastReceiver();
    }    

    @Override
    protected void onStop() {
        super.onStop();
        if(broadcastReceiver != null) {
            //unregisterReceiver(broadcastReceiver);
        }
    }
}
public class BroadcastReceiverLeakActivity2 extends AppCompatActivity {

    private BroadcastReceiver broadcastReceiver;

    private void registerBroadCastReceiver() {
        broadcastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                //your receiver code goes here!
            }
        };
        // ok: MSTG-CODE-8.1
        registerReceiver(broadcastReceiver, new IntentFilter("SmsMessage.intent.MAIN"));
    }
    
    @Override
    protected void onStart() {
        super.onStart();
        registerBroadCastReceiver();
    }    

    @Override
    protected void onStop() {
        super.onStop();
        if(broadcastReceiver != null) {
            unregisterReceiver(broadcastReceiver);
        }
    }
}
