package org.owasp.mastestapp;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MastgTest.kt */
@Metadata(d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\b\u0007\u0018\u0000 \u000f2\u00020\u0001:\u0001\u000fB\u0007¢\u0006\u0004\b\u0002\u0010\u0003B\u0011\b\u0016\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0004\b\u0002\u0010\u0006J\u0006\u0010\t\u001a\u00020\bJ\u0018\u0010\n\u001a\u00020\u000b2\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\f\u001a\u00020\rH\u0016J\b\u0010\u000e\u001a\u00020\rH\u0016R\u000e\u0010\u0007\u001a\u00020\bX\u0082D¢\u0006\u0002\n\u0000¨\u0006\u0010"}, d2 = {"Lorg/owasp/mastestapp/MastgTest;", "Landroid/os/Parcelable;", "<init>", "()V", "parcel", "Landroid/os/Parcel;", "(Landroid/os/Parcel;)V", "sensitiveString", "", "mastgTest", "writeToParcel", "", "flags", "", "describeContents", "CREATOR", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
/* loaded from: classes3.dex */
public final class MastgTest implements Parcelable {
    public static final int $stable = 0;

    /* renamed from: CREATOR, reason: from kotlin metadata */
    public static final Companion INSTANCE = new Companion(null);
    private final String sensitiveString;

    public MastgTest() {
        this.sensitiveString = "Hello from the OWASP MASTG Test app.";
        Log.d("MASTG-DEMO", "Legitimate 'MastgTest' object created/deserialized.");
        mastgTest();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public MastgTest(Parcel parcel) {
        this();
        Intrinsics.checkNotNullParameter(parcel, "parcel");
    }

    public final String mastgTest() {
        Log.d("MASTG-DEMO", "Executing legitimate business logic: " + this.sensitiveString);
        return this.sensitiveString;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* compiled from: MastgTest.kt */
    @Metadata(d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0007H\u0016J\u001d\u0010\b\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\t2\u0006\u0010\n\u001a\u00020\u000bH\u0016¢\u0006\u0002\u0010\f¨\u0006\r"}, d2 = {"Lorg/owasp/mastestapp/MastgTest$CREATOR;", "Landroid/os/Parcelable$Creator;", "Lorg/owasp/mastestapp/MastgTest;", "<init>", "()V", "createFromParcel", "parcel", "Landroid/os/Parcel;", "newArray", "", "size", "", "(I)[Lorg/owasp/mastestapp/MastgTest;", "app_debug"}, k = 1, mv = {2, 0, 0}, xi = 48)
    /* renamed from: org.owasp.mastestapp.MastgTest$CREATOR, reason: from kotlin metadata */
    public static final class Companion implements Parcelable.Creator<MastgTest> {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @Override // android.os.Parcelable.Creator
        public MastgTest createFromParcel(Parcel parcel) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            return new MastgTest(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public MastgTest[] newArray(int size) {
            return new MastgTest[size];
        }
    }
}
