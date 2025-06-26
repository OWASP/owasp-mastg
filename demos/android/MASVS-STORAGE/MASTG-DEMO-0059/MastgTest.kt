package org.owasp.mastestapp

import android.content.Context

class MastgTest (private val context: Context){

    private val sensitiveData: String =
        "These are some strings which are considered sensitive data. They should not be stored insecurely: \n" +
                "Artifactory: AKCp73pL4kpx91TSG1v2J5sLz6rHbHCVF5S3A\n" +
                "AWSKey: AKIAIOSFODNN7EXAMPLE\n" +
                "AzureStorageKey: Eby8vdM02xNO+G6CZDtl/JlEt2k='ExAmPlEkEy\n" +
                "BasicAuth: dXNlcm5hbWU6cGFzc3dvcmQ=\n" +
                "Cloudant: 4c9d0a20f5-2f52-4be1-9a27-19e40bd2ac83-bluemix\n" +
                "DiscordBotToken: ODkxMjI2OTg0ODIxNzcyMDY4.YfP-cw.k5FVSFOjVC0GZ6qHwWr2hsU-34U\n" +
                "GitHubToken: ghp_1234567890abcdefghijklmnOPQRSTUV\n" +
                "GitLabToken: glpat-12abc34XYZ5efGHIJKL67mnOpQrSt\n" +
                "Base64HighEntropyString: QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n" +
                "HexHighEntropyString: 4a1d2c1f9f835c82d15694e445f7cd9f1db7f6a7\n" +
                "IbmCloudIam: eyJraWQiOiI2Nzg5eCIsImFsZyI6IkhTMjU2In0\n" +
                "IbmCosHmac: OUnS6XcBYLArEtyHPtH8/Sdgr7EjIUhe7gZtnrZj\n" +
                "IPPrivate: 192.168.1.1\n" +
                "IPPrivate: 172.16.4.5.0\n" +
                "IPPrivate: 10.0.2.5\n" +
                "IPLocalHost: 127.0.0.1\n" +
                "JwtToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImlhdCI6MTYxNzA1NjgwMCwiZXhwIjoxNjE3MDU3MDAwfQ.sJgFhsr5d2JG1hKOnwzzd8qzNx56Z76pRVKkJVGmPAI\n" +
                "Mailchimp: 9d7c1b4fd8bbddad8ecf841d-us20\n" +
                "Npm: npm_AZ4D3XFUGYD2HC3YBWLNLFIE\n" +
                "OpenAI: sk-2t1HcLdKzRrn0pOI5GwIaRn8Z2Xgf9\n" +
                "PrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=\n" +
                "PypiToken: pypi-AgENdGVzdC10b2tlbi0xMjM0\n" +
                "SendGrid: SG.dummykey12345Uwv5ecA7QG-3W4dUMG\n" +
                "Slack: xoxb-123456789012-1234567890123-ABCDEFG12345678\n" +
                "Softlayer: abcdefghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890abcdef\n" +
                "SquareOAuth: sq0atp-1rLNX1q4TaLRcS1Xr1kWlA\n" +
                "Stripe: sk_test_4eC39HqLyjWDarjtT1zdp7dc\n" +
                "TelegramBotToken: 123456789:AAHojBo45KxlmdmpI3XlVu3iTDnjFPlwd\n" +
                "TwilioKey: SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n" +
                "PrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=\n" +
                "PrivateKey: -----BEGIN RSA PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN RSA PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN DSA PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN DSA PUBLIC KEY-----\n" +
                "PrivateKey: -----BEGIN EC PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN EC PUBLIC KEY-----\n" +
                "PrivateKey: -----BEGIN DH PARAMETERS-----\n" +
                "PrivateKey: -----BEGIN PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN EC PRIVATE KEY-----\n" +
                "PrivateKey: -----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "PrivateKey: -----END RSA PRIVATE KEY-----\n" +
                "PrivateKey: -----END EC PRIVATE KEY-----\n" +
                "PrivateKey: Proc-Type: 4,ENCRYPTED\n"

    fun mastgTest(): String {
        val r = DemoResults("0059")

        try {
            val sharedPref =
                context.getSharedPreferences("MasSharedPref_Sensitive_Data", Context.MODE_PRIVATE)
            val editor = sharedPref.edit()
            editor.putString("SensitiveData", sensitiveData)
            editor.apply()
            r.add(Status.FAIL, "Sensitive data has been written to the sandbox using putString().")


            val stringSet: MutableSet<String> = HashSet()
            stringSet.add(sensitiveData)
            editor.putStringSet("SensitiveDataStringSet", stringSet)
            editor.apply()

            r.add(Status.FAIL, "Sensitive data has been written to the sandbox using putStringSet().")
        }
        catch (e: Exception){
            r.add(Status.ERROR, e.toString())
        }
        return r.toJson()
    }

}
