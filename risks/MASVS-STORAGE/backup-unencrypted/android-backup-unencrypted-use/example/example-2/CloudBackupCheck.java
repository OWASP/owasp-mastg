// SUMMARY: Example demonstrates checking if sensitive information might be backed up to the cloud without encryption.

// Use SharedPreferences to store sensitive data
SharedPreferences prefs = getSharedPreferences("user_prefs", MODE_PRIVATE);
SharedPreferences.Editor editor = prefs.edit();
editor.putString("authToken", "sensitive_token_here"); // Potential risk if cloud backups are enabled.
editor.apply();

// Recommendation: Exclude sensitive data from auto backups or encrypt before backup.