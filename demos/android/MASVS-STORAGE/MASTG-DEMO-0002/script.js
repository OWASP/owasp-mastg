// Intercept libc`open to make sure we cover all Java's APIs
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter(args) {
        const external_paths = ['/sdcard', '/storage/emulated']
        const path = Memory.readCString(ptr(args[0]));
        external_paths.forEach(external_path => {
            if(path.indexOf(external_path) == 0){
                console.log('[WARNING] Opening a file from external storage at:', path)
                Java.performNow(function() {
                    console.log("Invoked from: "+Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
                });
            }
        });
    }
});

Java.perform(function() {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver["insert"].overload('android.net.Uri', 'android.content.ContentValues').implementation = function (uri, values) {
        var result = this.insert(uri, values);
        console.log('[WARNING] Opening a file with MediaStore at:', result)
        Java.performNow(function() {
            console.log("Invoked from: "+Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
        });
        return result;
    };
});
