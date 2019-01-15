package sg.vp.owasp_mobile.OMTG_Android;

import android.app.Application;
import android.content.Context;

import org.acra.*;
import org.acra.annotation.*;
import org.acra.sender.HttpSender;

@ReportsCrashes(
        formUri = "https://sushi2k.cloudant.com/acra/_design/acra-storage/_update/report",
        reportType = HttpSender.Type.JSON,
        httpMethod = HttpSender.Method.POST,
        formUriBasicAuthLogin = "MmHZOqxAdT0mWSmXddYBdLPDo",
        formUriBasicAuthPassword = "MmHZOqxAdT0mWSmXddYBdLPDo",
        customReportContent = {
                ReportField.APP_VERSION_CODE,
                ReportField.APP_VERSION_NAME,
                ReportField.ANDROID_VERSION,
                ReportField.PACKAGE_NAME,
                ReportField.REPORT_ID,
                ReportField.BUILD,
                ReportField.STACK_TRACE,
                ReportField.DISPLAY,
                ReportField.TOTAL_MEM_SIZE,
                ReportField.AVAILABLE_MEM_SIZE
        },
        mode = ReportingInteractionMode.SILENT
)


// ACRA stands for Application Crash Reports for Android. This library helps your software send crash reports to a backend of your choice.
public class MyApplication extends Application {
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        // The following line triggers the initialization of ACRA
        ACRA.init(this);
    }
}