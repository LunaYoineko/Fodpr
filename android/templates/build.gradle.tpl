def buildAsLibrary = project.hasProperty('BUILD_AS_LIBRARY');
def buildAsApplication = !buildAsLibrary
if (buildAsApplication) {
    apply plugin: 'com.android.application'
}
else {
    apply plugin: 'com.android.library'
}

android {
    if (buildAsApplication) {
        namespace "@PACKAGE@"
    }
    compileSdkVersion 34
    defaultConfig {
        minSdkVersion 24
        targetSdkVersion 34
        versionCode 1
        versionName "1.0"
        // Native libraries (libSDL2.so / libmain.so) are cross-compiled
        // outside Gradle and placed in src/main/jniLibs/<abi>/ by build_apk.sh.
        ndk {
            abiFilters 'arm64-v8a'
        }
    }
    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
    lint {
        abortOnError false
    }
}

dependencies {
    implementation fileTree(include: ['*.jar'], dir: 'libs')
}
