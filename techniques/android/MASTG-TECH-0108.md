---
title: Taint Analysis
platform: android
---

Taint analysis is an information flow analysis technique that tracks the flow of sensitive information within a program. For example, it can determine whether geolocation data collected in an Android app is being transmitted to third-party domains.

In taint analysis, data flows from a "source" to a "sink". A source is where sensitive information originates, and a sink is where this information is ultimately utilized. For instance, we can determine if the device ID retrieved by a `getDeviceId()` function is transmitted as a text message via another function `sendTextMessage()`. In this scenario, `getDeviceId()` is the source, and `sendTextMessage()` is the sink. If a direct path exists between them, it's called a _leak_.

In large applications, manual information flow analysis can be very time consuming and inaccurate. Taint analysis automates this, with two main methods: static and dynamic. The former examines code without running it, offering broad coverage but potentially yielding false positives. In contrast, dynamic analysis observes real-time application execution, providing actual context but possibly overlooking untriggered issues. A thorough comparison of these techniques is beyond this section's scope.

There are multiple tools which perform taint analysis on native code, including [Triton](https://github.com/jonathansalwan/Triton "Triton") and [bincat](https://github.com/airbus-seclab/bincat "bincat"). However, in this section, we'll primarily focus on Android Java code and utilize [FlowDroid](../../apps/android/MASTG-APP-0099.md "FlowDroid") for the taint analysis. Another notable tool supporting taint analysis for Android apps is [GDA](https://github.com/charles2gan/GDA-android-reversing-Tool/wiki/GDA-Static-Taint-Analysis "GDA").

For our demonstration, we'll use [FlowDroid](../../tools/android/MASTG-TOOL-0099.md)'s command line tool to perform taint analysis on the [InsecureShop v1.0](https://github.com/hax0rgb/InsecureShop/releases/tag/v1.0 "InsecureShop") application.

The InsecureShop app accepts a username and password as input and stores them in the app's shared preferences. In our taint analysis, we're interested in how this stored username and password are used. In this context, the username and password are the sensitive information, and reading from shared preferences is the source. The sink in this analysis could be various operations, such as sending info over the network, transmitting info via an `Intent`, or storing info in an external file.

To use FlowDroid, firstly, we need to provide an input list of potential sources and sinks to evaluate for. In our case, _reading from shared preferences_ will be the source, while _adding parameters to an `Intent`_ will be the sink. The configuration file will look as follows (we'll name it "source_sink.txt"):

```Jimple
<android.content.SharedPreferences: java.lang.String getString(java.lang.String, java.lang.String)> -> _SOURCE_

<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.CharSequence)> -> _SINK_
<android.content.Intent: android.content.Intent putExtra(java.lang.String,char)> -> _SINK_
<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)> -> _SINK_
```

To invoke FlowDroid via the command line, use the following command:

```shell
java -jar soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar \
    -a InsecureShop.apk \
    -p Android/Sdk/platforms \
    -s source_sink.txt


[main] INFO soot.jimple.infoflow.android.SetupApplication$InPlaceInfoflow - The sink virtualinvoke r2.<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>("password", $r5) in method <com.insecureshop.AboutUsActivity: void onSendData(android.view.View)> was called with values from the following sources:

[main] INFO soot.jimple.infoflow.android.SetupApplication$InPlaceInfoflow - - $r1 = interfaceinvoke $r2.<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>("password", "") in method <com.insecureshop.util.Prefs: java.lang.String getPassword()>

...

[main] INFO soot.jimple.infoflow.android.SetupApplication$InPlaceInfoflow - The sink virtualinvoke r2.<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>("username", $r4) in method <com.insecureshop.AboutUsActivity: void onSendData(android.view.View)> was called with values from the following sources:

[main] INFO soot.jimple.infoflow.android.SetupApplication$InPlaceInfoflow - - $r1 = interfaceinvoke $r2.<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>("username", "") in method <com.insecureshop.util.Prefs: java.lang.String getUsername()>

...

[main] INFO soot.jimple.infoflow.android.SetupApplication - Found 2 leaks
```

The output also uses the [jimple intermediate representation](https://www.sable.mcgill.ca/soot/doc/soot/jimple/Jimple.html "Jimple") and reveals two leaks in the application, each corresponding to the username and password. Given that the InsecureShop app is open-source, we can refer to its source code to validate the findings, as shown below:

```java
// file: AboutActivity.kt

fun onSendData(view: View) {
        val userName = Prefs.username!!
        val password = Prefs.password!!

        val intent = Intent("com.insecureshop.action.BROADCAST")
        intent.putExtra("username", userName)
        intent.putExtra("password", password)
        sendBroadcast(intent)

        textView.text = "InsecureShop is an intentionally designed vulnerable android app built in Kotlin."

    }
```

Taint analysis is especially beneficial for automating data flow analysis in intricate applications. However, given the complexity of some apps, the accuracy of such tools can vary. Thus, it's essential for reviewers to find a balance between the accuracy of tools and the time spent on manual analysis.
