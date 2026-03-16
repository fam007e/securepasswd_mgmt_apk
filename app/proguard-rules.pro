# Keep the PasswordEntry class and all its members because they are used by JNI
-keep class com.securepasswd.mgmt.PasswordEntry {
    <init>(...);
    *;
}

# Keep all native methods in CoreInterop
-keepclassmembers class com.securepasswd.mgmt.CoreInterop {
    native <methods>;
}
