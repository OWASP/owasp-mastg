/**
 * Makes a hex dump of a byte array. The dump is limited by the length parameter.
 * @param {Uint8Array} bytes - Byte array to be decoded to hexadecimal.
 * @param {number} length - Number of bytes which will be decoded.
 * @returns {string} The hexadecimal decoded bytes (e.g., "0x22aa3482ef...")
 */
function byteArrayHexDump(bytes, length) {
  var appendix = "...";
  if (bytes.length < length) {
    length = bytes.length;
    appendix = "";
  }

  var hexString = "0x";
  for (var i = 0; i < length; i++) {
    hexString =
      hexString + ("0" + (bytes[i] & 0xff).toString(16)).slice(-2);
  }

  return hexString + appendix;
}

/**
 * Converts a byte value to its uri-encoded representation
 * @param {number} byte - The byte value to encode (0-255)
 * @returns {string} The uri-encoded string (e.g., "%20", "%0A")
 */
function getUriCode(byte) {
  const text = byte.toString(16);
  if (byte < 16) {
    return "%0" + text;
  }
  return "%" + text;
}

/**
 * Tries to decode a byte array to either a string or a hex dump depending on the content of the array.
 * @param {Uint8Array} bytes - Byte array to be decoded to hexadecimal.
 * @param {number} length - Number of bytes which will be decoded.
 * @returns {string} The decoded bytes (e.g., "This is some decoded string." or "0x22aa3482ef...")
 */
function byteToString(bytes, length) {
  if (bytes.length < length) {
    length = bytes.length;
  }

  try {
    // try to decode strings
    var result = "";
    for (var i = 0; i < length; ++i) {
      result += getUriCode(bytes[i]);
    }
    return decodeURIComponent(result).replace(/\0.*$/g, "");
  } catch (e) {
    // make a hex dump in case, the byte array contains raw binary data
    return byteArrayHexDump(bytes, length);
  }
}

/**
 * Decodes a Java object according to its type.
 * @param {string} type - Java type of the value (e.g., "java.util.Set", "java.lang.String" or "int")
 * @param {Object} value - Reference to the object.
 * @returns {string} The type-appropriate decoded string (e.g., "[1,50,21]", "Hello World" or "-12")
 */
function decodeValue(type, value) {
  var readableValue = "";

  try {
    if (value == null) {
      readableValue = "void";
    } else {
      switch (type) {
        case "java.util.Set":
          readableValue = value.toArray().toString();
          break;

        case "java.util.Map":
          var entrySet = value.entrySet();
          readableValue = entrySet.toArray().toString();
          break;

        case "[B":
          // for performance reasons only decode the first 256 bytes of the full byte array
          readableValue = byteToString(value, 256);
          break;

        case "[C":
          readableValue = "";
          for (var i in value) {
            readableValue = readableValue + value[i];
          }
          break;

        case "java.io.File":
          readableValue = value.getAbsolutePath();
          break;

        case "java.util.Date":
          var DateFormat = Java.use('java.text.DateFormat');
          var formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM.value, DateFormat.SHORT.value);
          readableValue = formatter.format(value);
          break;

        case "androidx.sqlite.db.SupportSQLiteQuery":
          readableValue = value.getSql();
          break;

        case "android.content.ClipData$Item":
          readableValue = value.getText().toString();
          break;

        case "androidx.datastore.preferences.core.Preferences$Key":
        case "java.lang.Object":
        case "android.net.Uri":
        case "java.lang.CharSequence":
          readableValue = value.toString();
          break;

        case "java.security.PrivateKey":
          //TODO: Access key info
          readableValue = value;
          break;

        case "[Ljava.lang.Object;":
          var out = "";
          for (var i in value) {
            out = out + value[i] + ", ";
          }
          readableValue = out;
          break;

        case "java.util.Enumeration":
          var elements = [];
          while (value.hasMoreElements()) {
            elements.push(value.nextElement().toString());
          }
          readableValue = JSON.stringify(elements);
          break;

        case "android.database.Cursor":
          readableValue = decodeCursor(value);
          break;

        default:
          readableValue = value;
          break;
      }
    }
  } catch (e) {
    console.error("Value decoding exception: " + e);
    readableValue = value;
  }
  return readableValue;
}

/**
 * Decodes a `android.database.Cursor` object.
 * @param {object} value - Reference to the object.
 * @returns {string} The decoded rows and columns.
 */
function decodeCursor(value){
  var out = "";
  var cursor = value;
  var originalCursorPosition = cursor.getPosition();

  // rows
  for (var i = 0; i < cursor.getColumnCount(); i++) {
    var columnName = cursor.getColumnName(i);
    out = out + columnName + " | ";
  }

  out = out + "\n----------------------\n";

  // columns
  if (cursor.moveToFirst()) {
    do {
      for (var i = 0; i < cursor.getColumnCount(); i++) {
        try {
          var columnValue = cursor.getString(i);
          out = out + columnValue + " | ";
        } catch (e) {
          out = out + " | ";
        }
      }
      out = out + "\n";
    } while (cursor.moveToNext());

    cursor.move(originalCursorPosition);
  }
  return out;
}

/**
 * Decodes a Java values according to their types.
 * @param {[string]} types - Java types of the value (e.g., ["java.util.Set", "java.lang.String", "int"])
 * @param {[string]]} value - Reference to the objects.
 * @returns {[string]} The type-appropriate decoded strings (e.g., ["java.util.Set":"[1,50,21]", "java.lang.String":"Hello World", "int":"-12"])
 */
function decodeArguments(types, args) {
  var parameters = [];
  for (var i in types) {
    var type = types[i];
    var parameter = { type: type, value: decodeValue(type, args[i]) };
    parameters.push(parameter);
  }
  return parameters;
}

