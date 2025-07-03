package org.owasp.mastestapp

import android.content.Context
import android.content.SharedPreferences
import java.util.HashSet

class MastgTest(private val context: Context) {
    private val sensitiveData: String = """These are some strings which are considered sensitive data. They should not be stored insecurely: 
Artifactory: AKCp73pL4kpx91TSG1v2J5sLz6rHbHCVF5S3A
AWSKey: AKIAIOSFODNN7EXAMPLE
AzureStorageKey: Eby8vdM02xNO+G6CZDtl/JlEt2k='ExAmPlEkEy
BasicAuth: dXNlcm5hbWU6cGFzc3dvcmQ=
Cloudant: 4c9d0a20f5-2f52-4be1-9a27-19e40bd2ac83-bluemix
DiscordBotToken: ODkxMjI2OTg0ODIxNzcyMDY4.YfP-cw.k5FVSFOjVC0GZ6qHwWr2hsU-34U
GitHubToken: ghp_1234567890abcdefghijklmnOPQRSTUV
GitLabToken: glpat-12abc34XYZ5efGHIJKL67mnOpQrSt
Base64HighEntropyString: QWxhZGRpbjpvcGVuIHNlc2FtZQ==
HexHighEntropyString: 4a1d2c1f9f835c82d15694e445f7cd9f1db7f6a7
IbmCloudIam: eyJraWQiOiI2Nzg5eCIsImFsZyI6IkhTMjU2In0
IbmCosHmac: OUnS6XcBYLArEtyHPtH8/Sdgr7EjIUhe7gZtnrZj
IPPrivate: 192.168.1.1
IPPrivate: 172.16.4.5.0
IPPrivate: 10.0.2.5
IPLocalHost: 127.0.0.1
JwtToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImlhdCI6MTYxNzA1NjgwMCwiZXhwIjoxNjE3MDU3MDAwfQ.sJgFhsr5d2JG1hKOnwzzd8qzNx56Z76pRVKkJVGmPAI
Mailchimp: 9d7c1b4fd8bbddad8ecf841d-us20
Npm: npm_AZ4D3XFUGYD2HC3YBWLNLFIE
OpenAI: sk-2t1HcLdKzRrn0pOI5GwIaRn8Z2Xgf9
PrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=
PypiToken: pypi-AgENdGVzdC10b2tlbi0xMjM0
SendGrid: SG.dummykey12345Uwv5ecA7QG-3W4dUMG
Slack: xoxb-123456789012-1234567890123-ABCDEFG12345678
Softlayer: abcdefghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890abcdef
SquareOAuth: sq0atp-1rLNX1q4TaLRcS1Xr1kWlA
Stripe: sk_test_4eC39HqLyjWDarjtT1zdp7dc
TelegramBotToken: 123456789:AAHojBo45KxlmdmpI3XlVu3iTDnjFPlwd
TwilioKey: SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
PrivateKey: MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=
PrivateKey: -----BEGIN RSA PRIVATE KEY-----
PrivateKey: -----BEGIN RSA PRIVATE KEY-----
PrivateKey: -----BEGIN DSA PRIVATE KEY-----
PrivateKey: -----BEGIN DSA PUBLIC KEY-----
PrivateKey: -----BEGIN EC PRIVATE KEY-----
PrivateKey: -----BEGIN EC PUBLIC KEY-----
PrivateKey: -----BEGIN DH PARAMETERS-----
PrivateKey: -----BEGIN PRIVATE KEY-----
PrivateKey: -----BEGIN EC PRIVATE KEY-----
PrivateKey: -----BEGIN ENCRYPTED PRIVATE KEY-----
PrivateKey: -----END RSA PRIVATE KEY-----
PrivateKey: -----END EC PRIVATE KEY-----
PrivateKey: Proc-Type: 4,ENCRYPTED"""

    fun mastgTest(): String {
        try {
            val sharedPref = context.getSharedPreferences("MasSharedPref_Sensitive_Data", Context.MODE_PRIVATE)
            val editor = sharedPref.edit()
            editor.putString("SensitiveData", sensitiveData)
            editor.apply()
            
            val stringSet = HashSet<String>()
            stringSet.add(sensitiveData)
            editor.putStringSet("SensitiveDataStringSet", stringSet)
            editor.apply()
            
            return "Sensitive data has been written to the sandbox."
        } catch (e: Exception) {
            return "Sensitive data has been written to the sandbox."
        }
    }
}