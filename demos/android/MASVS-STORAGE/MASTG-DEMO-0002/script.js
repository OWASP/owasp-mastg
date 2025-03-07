// It calls Java.performNow to ensure Java classes are available.
function printBacktrace(maxLines = 8) {
    Java.performNow(() => {
        let Exception = Java.use("java.lang.Exception");
        let stackTrace = Exception.$new().getStackTrace().toString().split(",");
        console.log("\nBacktrace:");
        for (let i = 0; i < Math.min(maxLines, stackTrace.length); i++) {
            console.log(stackTrace[i]);
        }
    });
}

Java.perform(() => {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver["insert"].overload('android.net.Uri', 'android.content.ContentValues').implementation = function(uri, values) {
        let result = this.insert(uri, values);
        console.log(`\n[*] ContentResolver.insert called to open a file via MediaStore at: ${result}`);
        printBacktrace();
        return result;
    };

});

Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter: function(args) {
        const external_paths = ['/sdcard', '/storage/emulated'];
        const path = Memory.readCString(ptr(args[0]));
        external_paths.forEach(external_path => {
            if (path.indexOf(external_path) === 0) {
                console.log(`\n[*] open called to open a file from external storage at: ${path}`);
                printBacktrace(15);
            }
        });
    }
});
