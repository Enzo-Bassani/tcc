# Prototype build does not minify. Keep BouncyCastle if R8 is ever enabled.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
