package org.owasp.mastestapp

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.os.StrictMode


class MastgTest (private val context: Context){

    fun mastgTest(): String {
        enableStrictMode()
        triggerSqliteCursorLeak()
        
        System.gc() // Force garbage collection to trigger leak detection

        return "SUCCESS!!\n\nSQL Cursor leaked."
    }

    private fun enableStrictMode() {
        StrictMode.setVmPolicy(
            StrictMode.VmPolicy.Builder()
                .detectLeakedClosableObjects() // Detect leaked/unclosed SQLite objects
                .penaltyLog()                 // Log violations
                .build()
        )
    }

    private fun triggerSqliteCursorLeak() {
        val db: SQLiteDatabase = context.openOrCreateDatabase("test.db", Context.MODE_PRIVATE, null)
        db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
        db.execSQL("INSERT INTO users (name) VALUES ('Alice'), ('Bob')")

        // Create cursor, and intentionally do not close it
        val cursor = db.rawQuery("SELECT * FROM users", null)
    }
}
