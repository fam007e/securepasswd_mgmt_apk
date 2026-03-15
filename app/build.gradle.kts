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
        versionCode = 2026031501
        versionName = "2026.03.15"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                
                // Allow targeting specific ABIs via command line for faster CI/Dev builds
                val requestedAbi = project.findProperty("android.injected.abi.requested") as? String
                    ?: project.findProperty("target.abis") as? String
                if (requestedAbi != null) {
                    abiFilters(*requestedAbi.split(",").toTypedArray())
                }
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
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
            version = "3.30.3"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
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
