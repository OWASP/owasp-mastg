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

// Intercept libc's open to make sure we cover all Java I/O APIs
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

// Hook ContentResolver.insert to log ContentValues (including keys like _display_name, mime_type, and relative_path) and returned URI
Java.perform(() => {
    let ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function(uri, values) {
        console.log(`\n[*] ContentResolver.insert called with ContentValues:`);
        

        if (values.containsKey("_display_name")) {
            console.log(`\t_display_name: ${values.get("_display_name").toString()}`);
        }
        if (values.containsKey("mime_type")) {
            console.log(`\tmime_type: ${values.get("mime_type").toString()}`);
        }
        if (values.containsKey("relative_path")) {
            console.log(`\trelative_path: ${values.get("relative_path").toString()}`);
        }

        let result = this.insert(uri, values);
        console.log(`\n[*] ContentResolver.insert returned URI: ${result.toString()}`);
        printBacktrace();
        return result;
    };
});