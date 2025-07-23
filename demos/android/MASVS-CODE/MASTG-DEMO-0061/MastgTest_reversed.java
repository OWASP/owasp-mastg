package org.owasp.mastestapp;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.autofill.HintConstants;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Base64;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0007\u0018\u00002\u00020\u0001:\u0003\f\r\u000eB\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u0006\u0010\u0006\u001a\u00020\u0007J\u000e\u0010\b\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000bR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000f"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "", "context", "Landroid/content/Context;", "<init>", "(Landroid/content/Context;)V", "mastgTest", "", "processIntent", "", "intent", "Landroid/content/Intent;", "BaseUser", "AdminUser", "UserManager", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest {
    public static final int $stable = 8;
    private final Context context;

    public MastgTest(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    /* compiled from: MastgTest.kt */
    @Metadata(d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0017\u0018\u0000 \b2\u00020\u0001:\u0001\bB\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\b\u0006\u0010\u0007¨\u0006\t"}, d2 = {"Lorg/owasp/mastestapp/MastgTest$BaseUser;", "Ljava/io/Serializable;", HintConstants.AUTOFILL_HINT_USERNAME, "", "<init>", "(Ljava/lang/String;)V", "getUsername", "()Ljava/lang/String;", "Companion", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static class BaseUser implements Serializable {
        public static final int $stable = 0;
        private static final long serialVersionUID = 100;
        private final String username;

        public BaseUser(String username) {
            Intrinsics.checkNotNullParameter(username, "username");
            this.username = username;
        }

        public final String getUsername() {
            return this.username;
        }
    }

    /* compiled from: MastgTest.kt */
    @Metadata(d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0005\b\u0007\u0018\u0000 \u000b2\u00020\u0001:\u0001\u000bB\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005R\u001a\u0010\u0006\u001a\u00020\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\b\"\u0004\b\t\u0010\n¨\u0006\f"}, d2 = {"Lorg/owasp/mastestapp/MastgTest$AdminUser;", "Lorg/owasp/mastestapp/MastgTest$BaseUser;", HintConstants.AUTOFILL_HINT_USERNAME, "", "<init>", "(Ljava/lang/String;)V", "isAdmin", "", "()Z", "setAdmin", "(Z)V", "Companion", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class AdminUser extends BaseUser {
        private static final long serialVersionUID = 200;
        private boolean isAdmin;
        public static final int $stable = 8;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AdminUser(String username) {
            super(username);
            Intrinsics.checkNotNullParameter(username, "username");
        }

        /* renamed from: isAdmin, reason: from getter */
        public final boolean getIsAdmin() {
            return this.isAdmin;
        }

        public final void setAdmin(boolean z) {
            this.isAdmin = z;
        }
    }

    /* compiled from: MastgTest.kt */
    @Metadata(d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\bÇ\u0002\u0018\u00002\u00020\u0001B\t\b\u0003¢\u0006\u0004\b\u0002\u0010\u0003R\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\t¨\u0006\n"}, d2 = {"Lorg/owasp/mastestapp/MastgTest$UserManager;", "", "<init>", "()V", "currentUser", "Lorg/owasp/mastestapp/MastgTest$BaseUser;", "getCurrentUser", "()Lorg/owasp/mastestapp/MastgTest$BaseUser;", "setCurrentUser", "(Lorg/owasp/mastestapp/MastgTest$BaseUser;)V", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
    public static final class UserManager {
        public static final UserManager INSTANCE = new UserManager();
        private static BaseUser currentUser = new BaseUser("Standard User");
        public static final int $stable = 8;

        private UserManager() {
        }

        public final BaseUser getCurrentUser() {
            return currentUser;
        }

        public final void setCurrentUser(BaseUser baseUser) {
            Intrinsics.checkNotNullParameter(baseUser, "<set-?>");
            currentUser = baseUser;
        }
    }

    public final String mastgTest() {
        String status;
        BaseUser user = UserManager.INSTANCE.getCurrentUser();
        if ((user instanceof AdminUser) && ((AdminUser) user).getIsAdmin()) {
            status = "PRIVILEGED ADMIN!";
        } else {
            status = "(Not an Admin)";
        }
        String resultString = "Current User: " + user.getUsername() + "\nStatus: " + status + "\n\nVulnerability: Unwanted Object Deserialization is active.\nThe app will deserialize any 'BaseUser' subclass from the 'payload_b64' extra, overwriting the current user state.";
        Log.d("MASTG-TEST", resultString);
        return resultString;
    }

    public final void processIntent(Intent intent) throws ClassNotFoundException, IOException {
        Intrinsics.checkNotNullParameter(intent, "intent");
        if (intent.hasExtra("payload_b64")) {
            String b64Payload = intent.getStringExtra("payload_b64");
            Log.d("VULN_APP", "Received a base64 payload. Deserializing user object...");
            try {
                byte[] serializedPayload = Base64.getDecoder().decode(b64Payload);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedPayload));
                Object untrustedObject = ois.readObject();
                ois.close();
                if (untrustedObject instanceof BaseUser) {
                    UserManager.INSTANCE.setCurrentUser((BaseUser) untrustedObject);
                    Log.i("VULN_APP", "User state overwritten with deserialized object!");
                } else {
                    Log.w("VULN_APP", "Deserialized object was not a user. State unchanged.");
                }
            } catch (Exception e) {
                Log.e("VULN_APP", "Failed to deserialize payload", e);
            }
        }
    }
}
