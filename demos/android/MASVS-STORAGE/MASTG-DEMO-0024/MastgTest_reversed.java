package org.owasp.mastestapp;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.widget.EditText;
import android.widget.LinearLayout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(m69d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u000e\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0002\u001a\u00020\u0003R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\t"}, m70d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "mastgTest", "", "showPopup", "", "app_debug"}, m71k = 1, m72mv = {1, 9, 0}, m74xi = 48)
/* loaded from: classes4.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    public final String mastgTest() {
        showPopup(this.context);
        return "The popup contains caching input fields";
    }

    public final void showPopup(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(1);
        layout.setPadding(50, 20, 50, 20);
        EditText $this$showPopup_u24lambda_u241 = new EditText(context);
        $this$showPopup_u24lambda_u241.setHint("Enter password");
        $this$showPopup_u24lambda_u241.setInputType(192);
        EditText $this$showPopup_u24lambda_u242 = new EditText(context);
        $this$showPopup_u24lambda_u242.setHint("Enter passcode");
        $this$showPopup_u24lambda_u242.setInputType(2);
        layout.addView($this$showPopup_u24lambda_u241);
        layout.addView($this$showPopup_u24lambda_u242);
        new AlertDialog.Builder(context).setTitle("Sign Up Form").setView(layout).setPositiveButton("Sign Up", new DialogInterface.OnClickListener() { // from class: org.owasp.mastestapp.MastgTest$$ExternalSyntheticLambda0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MastgTest.showPopup$lambda$3(dialogInterface, i);
            }
        }).setNegativeButton("Cancel", (DialogInterface.OnClickListener) null).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void showPopup$lambda$3(DialogInterface dialogInterface, int i) {
    }
}
