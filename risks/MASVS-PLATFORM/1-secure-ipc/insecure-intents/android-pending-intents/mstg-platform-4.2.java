public class Test{

    public void test1(){
        Intent intent = new Intent(applicationContext, SomeActivity.class);     // base intent

        // create a pending intent
        PendingIntent pendingIntent = PendingIntent.getActivity(applicationContext, 0, intent, 67108868);

        PendingIntent pendingIntent = PendingIntent.getActivity(applicationContext, 0, intent, 1073741828);

        // send the pending intent to another app
        Intent anotherIntent = new Intent();
        anotherIntent.setClassName("other.app", "other.app.MainActivity");
        anotherIntent.putExtra("pendingIntent", pendingIntent);
        startActivity(anotherIntent);
    }
}