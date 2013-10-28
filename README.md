dextractor
==========

A simple DEX information extractor

- Documentation about the DEX file format: http://source.android.com/devices/tech/dalvik/dex-format.html
- Overview about APK and DEX file format: http://www.amazon.com/Decompiling-Android-Godfrey-Nolan/dp/1430242485
- Axelle Aprville "Hidden Methods" @Hack.lu-2013: http://t.co/PO1QnkqbTw
- Jurriaan Bremer "Abusing Dalvik" @Hack.lu-2013: http://archive.hack.lu/2013/AbusingDalvikBeyondRecognition.pdf

Main goals:

  - DEX corruption identifier
  - Methods signature & name extractor: the main problem is the "obfuscation" method presented at Hack.lu 2013 by Axelle Aprville to hide a Java method to decompilers (even IDA Pro fails to identify it, at first try)
  - General information extraction
