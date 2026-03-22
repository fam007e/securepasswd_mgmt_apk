@file:Suppress("UnstableApiUsage")

import com.android.build.api.dsl.ApplicationExtension

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

extensions.configure<ApplicationExtension>("android") {
    namespace = "com.securepasswd.mgmt"
    compileSdk = 36
    ndkVersion = "25.1.8937393"

    defaultConfig {
        applicationId = "com.securepasswd.mgmt"
        minSdk = 26
        targetSdk = 35
        versionCode = 2026031810 // Base version code for ABI splitting logic
        versionName = "2026.03.18"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
            generatedDensities?.clear()
        }

        ndk {
            // Ensure we only build for these ABIs even when splits are disabled
            abiFilters.addAll(listOf("armeabi-v7a", "arm64-v8a"))
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                cppFlags += "-Wno-macro-redefined"
                cFlags += "-Wno-macro-redefined"
                
                // Allow targeting specific ABIs via command line for faster CI/Dev builds
                val requestedAbi = project.findProperty("android.injected.abi.requested") as? String
                    ?: project.findProperty("target.abis") as? String
                if (requestedAbi != null) {
                    abiFilters(*requestedAbi.split(",").toTypedArray())
                }
            }
        }
    }

    val isSplitEnabled = project.hasProperty("enableSplits")

    splits {
        abi {
            isEnable = isSplitEnabled
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            vcsInfo.include = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // ABI-specific version code logic
    // Using the project's 'android' extension to access applicationVariants
    project.extra.set("android.applicationVariants", true) 
}

// Access applicationVariants to override versionCode for each ABI
(extensions.getByName("android") as com.android.build.gradle.BaseExtension).apply {
    (this as com.android.build.gradle.AppExtension).applicationVariants.all {
        outputs.forEach { output ->
            val outputImpl = output as com.android.build.gradle.internal.api.ApkVariantOutputImpl
            val abi = outputImpl.getFilter("ABI")
            val abiMultiplier = when (abi) {
                "armeabi-v7a" -> 1
                "arm64-v8a" -> 2
                else -> 0 // Universal / Fat
            }
            // Use addition instead of multiplication by 10 to avoid Int overflow
            // with large date-based versionCode (e.g., 2026031810)
            outputImpl.versionCodeOverride = (defaultConfig.versionCode ?: 0) + abiMultiplier
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation(platform("androidx.compose:compose-bom:2026.03.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // CameraX
    val cameraxVersion = "1.5.3"
    implementation("androidx.camera:camera-core:${cameraxVersion}")
    implementation("androidx.camera:camera-camera2:${cameraxVersion}")
    implementation("androidx.camera:camera-lifecycle:${cameraxVersion}")
    implementation("androidx.camera:camera-view:${cameraxVersion}")

    // ZXing (FOSS-compliant barcode scanning)
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.compose.material:material-icons-extended")

    // Force consistent version of concurrent-futures
    implementation("androidx.concurrent:concurrent-futures:1.2.0")
    implementation("androidx.concurrent:concurrent-futures-ktx:1.2.0")
    implementation("com.github.woheller69:FreeDroidWarn:V1.8")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")

    // Constraint to resolve conflict with concurrent-futures
    constraints {
        androidTestImplementation("androidx.concurrent:concurrent-futures:1.2.0")
        androidTestImplementation("androidx.concurrent:concurrent-futures-ktx:1.2.0")
    }
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.03.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

tasks.whenTaskAdded {
    if (name.contains("ArtProfile")) {
        enabled = false
    }
}
