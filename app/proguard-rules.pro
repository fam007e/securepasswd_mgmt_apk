# Keep the PasswordEntry class and all its members because they are used by JNI
-keep class com.securepasswd.mgmt.PasswordEntry {
    <init>(...);
    *;
}

# Keep all native methods in CoreInterop
-keepclassmembers class com.securepasswd.mgmt.CoreInterop {
    native <methods>;
}

# Fix R8 non-determinism
-keep class kotlinx.coroutines.CoroutineExceptionHandler
-keep class kotlinx.coroutines.internal.MainDispatcherFactory
