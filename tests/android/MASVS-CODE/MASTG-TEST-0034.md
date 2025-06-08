---
masvs_v1_id:
- MSTG-PLATFORM-8
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Testing Object Persistence
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

To test for [object persistence](../../../Document/0x05h-Testing-Platform-Interaction.md#object-persistence "Object Persistence") being used for storing sensitive information on the device, first identify all instances of object serialization and check if they carry any sensitive data. If yes, check if it is properly protected against eavesdropping or unauthorized modification.

There are a few generic remediation steps that you can always take:

1. Make sure that sensitive data has been encrypted and HMACed/signed after serialization/persistence. Evaluate the signature or HMAC before you use the data. See the chapter "[Android Cryptographic APIs](../../../Document/0x05e-Testing-Cryptography.md)" for more details.
2. Make sure that the keys used in step 1 can't be extracted easily. The user and/or application instance should be properly authenticated/authorized to obtain the keys. See the chapter "[Data Storage on Android](../../../Document/0x05d-Testing-Data-Storage.md)" for more details.
3. Make sure that the data within the de-serialized object is carefully validated before it is actively used (e.g., no exploit of business/application logic).

For high-risk applications that focus on availability, we recommend that you use `Serializable` only when the serialized classes are stable. Second, we recommend not using reflection-based persistence because

- the attacker could find the method's signature via the String-based argument
- the attacker might be able to manipulate the reflection-based steps to execute business logic.

## Static Analysis

### Object Serialization

Search the source code for the following keywords:

- `import java.io.Serializable`
- `implements Serializable`

### JSON

If you need to counter memory-dumping, make sure that very sensitive information is not stored in the JSON format because you can't guarantee prevention of anti-memory dumping techniques with the standard libraries. You can check for the following keywords in the corresponding libraries:

**`JSONObject`** Search the source code for the following keywords:

- `import org.json.JSONObject;`
- `import org.json.JSONArray;`

**`GSON`** Search the source code for the following keywords:

- `import com.google.gson`
- `import com.google.gson.annotations`
- `import com.google.gson.reflect`
- `import com.google.gson.stream`
- `new Gson();`
- Annotations such as `@Expose`, `@JsonAdapter`, `@SerializedName`,`@Since`, and `@Until`

**`Jackson`** Search the source code for the following keywords:

- `import com.fasterxml.jackson.core`
- `import org.codehaus.jackson` for the older version.

### ORM

When you use an ORM library, make sure that the data is stored in an encrypted database and the class representations are individually encrypted before storing it. See the chapters "[Data Storage on Android](../../../Document/0x05d-Testing-Data-Storage.md)" and "[Android Cryptographic APIs](../../../Document/0x05e-Testing-Cryptography.md)" for more details. You can check for the following keywords in the corresponding libraries:

**`OrmLite`** Search the source code for the following keywords:

- `import com.j256.*`
- `import com.j256.dao`
- `import com.j256.db`
- `import com.j256.stmt`
- `import com.j256.table\`

Please make sure that logging is disabled.

**`SugarORM`** Search the source code for the following keywords:

- `import com.github.satyan`
- `extends SugarRecord<Type>`
- In the AndroidManifest, there will be `meta-data` entries with values such as `DATABASE`, `VERSION`, `QUERY_LOG` and `DOMAIN_PACKAGE_NAME`.

Make sure that `QUERY_LOG` is set to false.

**`GreenDAO`** Search the source code for the following keywords:

- `import org.greenrobot.greendao.annotation.Convert`
- `import org.greenrobot.greendao.annotation.Entity`
- `import org.greenrobot.greendao.annotation.Generated`
- `import org.greenrobot.greendao.annotation.Id`
- `import org.greenrobot.greendao.annotation.Index`
- `import org.greenrobot.greendao.annotation.NotNull`
- `import org.greenrobot.greendao.annotation.*`
- `import org.greenrobot.greendao.database.Database`
- `import org.greenrobot.greendao.query.Query`

**`ActiveAndroid`** Search the source code for the following keywords:

- `ActiveAndroid.initialize(<contextReference>);`
- `import com.activeandroid.Configuration`
- `import com.activeandroid.query.*`

**`Realm`** Search the source code for the following keywords:

- `import io.realm.RealmObject;`
- `import io.realm.annotations.PrimaryKey;`

### Parcelable

Make sure that appropriate security measures are taken when sensitive information is stored in an Intent via a Bundle that contains a Parcelable. Use explicit Intents and verify proper additional security controls when using application-level IPC (e.g., signature verification, intent-permissions, crypto).

## Dynamic Analysis

There are several ways to perform dynamic analysis:

1. For the actual persistence: Use the techniques described in the data storage chapter.
2. For reflection-based approaches: Use @MASTG-TOOL-0001 to hook into the deserialization methods or add unprocessable information to the serialized objects to see how they are handled (e.g., whether the application crashes or extra information can be extracted by enriching the objects).
