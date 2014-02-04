android-encryption
==================

This project contains code to decrypt Android's Full Device Encryption. It is based on the original script released at the DEF CON 20 talk entitled '[Into the Droid](https://viaforensics.com/mobile-security/droid-gaining-access-android-user-data.html)' by Thomas Cannon. It includes enhancements from other authors and now calculates ESSIV correctly so all sectors in a partition can now be decrypted with the correct key.

Each Android device is different and this work does not support all of them as vendors implement encryption in different ways. It is also not (yet) an easy point and click solution, you need to understand what you are doing. Feel free to submit pull requests :)
