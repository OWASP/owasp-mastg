---
masvs_category: MASVS-PLATFORM
platform: android
title: Object Serialization
---

There are several ways to serialize an object on Android:

## Java Serializable API

An object and its data can be represented as a sequence of bytes. This is done in Java via [object serialization](https://developer.android.com/reference/java/io/Serializable.html "Serializable"). Serialization is not inherently secure. It is just a binary format (or representation) for locally storing data in a .ser file. Encrypting and signing HMAC-serialized data is possible as long as the keys are stored safely. Deserializing an object requires a class of the same version as the class used to serialize the object. After classes have been changed, the `ObjectInputStream` can't create objects from older .ser files. The example below shows how to create a `Serializable` class by implementing the `Serializable` interface.

```java
import java.io.Serializable;

public class Person implements Serializable {
  private String firstName;
  private String lastName;

  public Person(String firstName, String lastName) {
    this.firstName = firstName;
    this.lastName = lastName;
    }
  //..
  //getters, setters, etc
  //..

}
```

Now you can read/write the object with `ObjectInputStream`/`ObjectOutputStream` in another class.

## JSON

There are several ways to serialize the contents of an object to JSON. Android comes with the `JSONObject` and `JSONArray` classes. A wide variety of libraries, including [GSON](https://github.com/google/gson "Google Gson"), [Jackson](https://github.com/FasterXML/jackson-core "Jackson core"), [Moshi](https://github.com/square/moshi "Moshi"), can also be used. The main differences between the libraries are whether they use reflection to compose the object, whether they support annotations, whether the create immutable objects, and the amount of memory they use. Note that almost all the JSON representations are String-based and therefore immutable. This means that any secret stored in JSON will be harder to remove from memory.
JSON itself can be stored anywhere, e.g., a (NoSQL) database or a file. You just need to make sure that any JSON that contains secrets has been appropriately protected (e.g., encrypted/HMACed). See the chapter ["Data Storage on Android"](0x05d-Testing-Data-Storage.md) for more details. A simple example (from the GSON User Guide) of writing and reading JSON with GSON follows. In this example, the contents of an instance of the `BagOfPrimitives` is serialized into JSON:

```java
class BagOfPrimitives {
  private int value1 = 1;
  private String value2 = "abc";
  private transient int value3 = 3;
  BagOfPrimitives() {
    // no-args constructor
  }
}

// Serialization
BagOfPrimitives obj = new BagOfPrimitives();
Gson gson = new Gson();
String json = gson.toJson(obj);

// ==> json is {"value1":1,"value2":"abc"}

```

## XML

There are several ways to serialize the contents of an object to XML and back. Android comes with the `XmlPullParser` interface which allows for easily maintainable XML parsing. There are two implementations within Android: `KXmlParser` and `ExpatPullParser`. The [Android Developer Guide](https://developer.android.com/training/basics/network-ops/xml#java "Instantiate the parser") provides a great write-up on how to use them. Next, there are various alternatives, such as a `SAX` parser that comes with the Java runtime. For more information, see [a blogpost from ibm.com](https://www.ibm.com/developerworks/opensource/library/x-android/index.html "Working with XML on Android on IBM Developer").
Similarly to JSON, XML has the issue of working mostly String based, which means that String-type secrets will be harder to remove from memory. XML data can be stored anywhere (database, files), but do need additional protection in case of secrets or information that should not be changed. See the chapter "[Data Storage on Android](0x05d-Testing-Data-Storage.md)" for more details. As stated earlier: the true danger in XML lies in the [XML eXternal Entity (XXE)](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing "XML eXternal Entity attack (XXE)") attack as it might allow for reading external data sources that are still accessible within the application.

## ORM

There are libraries that provide functionality for directly storing the contents of an object in a database and then instantiating the object with the database contents. This is called Object-Relational Mapping (ORM). Libraries that use the SQLite database include

- [OrmLite](https://github.com/j256/ormlite-android "OrmLite"),
- [SugarORM](https://satyan.github.io/sugar/ "Sugar ORM"),
- [GreenDAO](https://github.com/greenrobot/greenDAO "GreenDAO") and
- [ActiveAndroid](https://github.com/pardom-zz/ActiveAndroid "ActiveAndroid").

[Realm](https://www.mongodb.com/docs/realm/sdk/java/ "Realm Java"), on the other hand, uses its own database to store the contents of a class. The amount of protection that ORM can provide depends primarily on whether the database is encrypted. See the chapter ["Data Storage on Android"](0x05d-Testing-Data-Storage.md) for more details. The Realm website includes a nice [example of ORM Lite](https://github.com/j256/ormlite-examples/tree/master/android/HelloAndroid "OrmLite example").

## Parcelable

[`Parcelable`](https://developer.android.com/reference/android/os/Parcelable.html "Parcelable") is an interface for classes whose instances can be written to and restored from a [`Parcel`](https://developer.android.com/reference/android/os/Parcel.html "Parcel"). Parcels are often used to pack a class as part of a `Bundle` for an `Intent`. Here's an Android developer documentation example that implements `Parcelable`:

```java
public class MyParcelable implements Parcelable {
     private int mData;

     public int describeContents() {
         return 0;
     }

     public void writeToParcel(Parcel out, int flags) {
         out.writeInt(mData);
     }

     public static final Parcelable.Creator<MyParcelable> CREATOR
             = new Parcelable.Creator<MyParcelable>() {
         public MyParcelable createFromParcel(Parcel in) {
             return new MyParcelable(in);
         }

         public MyParcelable[] newArray(int size) {
             return new MyParcelable[size];
         }
     };

     private MyParcelable(Parcel in) {
         mData = in.readInt();
     }
 }
```

Because this mechanism that involves Parcels and Intents may change over time, and the `Parcelable` may contain `IBinder` pointers, storing data to disk via `Parcelable` is not recommended.

## Protocol Buffers

[Protocol Buffers](https://developers.google.com/protocol-buffers/ "Google Documentation") by Google, are a platform- and language neutral mechanism for serializing structured data by means of the [Binary Data Format](https://developers.google.com/protocol-buffers/docs/encoding "Encoding").
There have been a few vulnerabilities with Protocol Buffers, such as [CVE-2015-5237](https://www.cvedetails.com/cve/CVE-2015-5237/ "CVE-2015-5237").
Note that Protocol Buffers do not provide any protection for confidentiality: there is no built in encryption.
