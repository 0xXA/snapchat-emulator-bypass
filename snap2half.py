import frida
import time
import sys

device = frida.get_device_manager().add_remote_device('127.0.0.1:1347')
pid = device.spawn(["com.snapchat.android"])
device.resume(pid)
session = device.attach(pid)
session1 = device.attach(pid,realm='emulated')
script = session.create_script("""
Java.perform(function() {
    var build = Java.use('android.os.Build');
    build.MANUFACTURER.value = 'Xiaomi';
    build.PRODUCT.value = 'aosp_miatoll';
    build.BRAND.value = 'Redmi';
    build.HARDWARE.value = 'mt6769';
    build.ID.value = 'RQ3A.210704.001';
    build.FINGERPRINT.value = 'Redmi/miatoll/miatoll:11/RQ3A.210704.001/V12.0.5.0.RJOMIXM:user/release-keys';
    build.BOARD.value = 'miatoll';
    Module.load('/data/app/com.snapchat.android-1/lib/arm64/libsnap2half_x64.so');
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function() {
            var text = this.readLine.call(this);
            if (text !== null) {
                    var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                    if (!shouldFakeRead) {
                        //send("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
            }
            return text;
        }

        var Sensors = Java.use("com.looksery.sdk.Sensors")
        Sensors.isEmulated.overload('android.hardware.Sensor').implementation = function() {
            return false;
        }

        var WebRtcAudioUtils = Java.use("org.webrtc.voiceengine.WebRtcAudioUtils")
        WebRtcAudioUtils.runningOnEmulator.overload().implementation = function(){
            return false;
        }

    function getRndInt(min,max) {
        return Math.floor(Math.random()*(max-min))+min;
    }
    var android_id = getRndInt(0x107118522d7fe0,0x507cc8522d7fe0);
    android_id = android_id.toString(16);

        var Secure = Java.use("android.provider.Settings$Secure");
        Secure.getString.implementation = function (contxt,strr) {
            if(strr.indexOf("android_id")>-1) {
                    //console.log("real Android_ID: "+this.getString(contxt,strr));
                    return android_id;
            } else {
                    return this.getString(contxt,strr);
            }
        }
});
""")
script1 = session1.create_script("""
    Java.perform(function() {
    var build = Java.use('android.os.Build');
    build.MANUFACTURER.value = 'Xiaomi';
    build.PRODUCT.value = 'aosp_miatoll';
    build.BRAND.value = 'Redmi';
    build.HARDWARE.value = 'mt6769';
    build.ID.value = 'RQ3A.210704.001';
    build.FINGERPRINT.value = 'Redmi/miatoll/miatoll:11/RQ3A.210704.001/V12.0.5.0.RJOMIXM:user/release-keys';
    build.BOARD.value = 'miatoll';
    Module.load('/data/app/com.snapchat.android-1/lib/arm64/libsnap2half_arm64.so');
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function() {
            var text = this.readLine.call(this);
            if (text !== null) {
                    var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                    if (!shouldFakeRead) {
                        //send("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
            }
            return text;
        }

        var Sensors = Java.use("com.looksery.sdk.Sensors")
        Sensors.isEmulated.overload('android.hardware.Sensor').implementation = function() {
            return false;
        }

        var WebRtcAudioUtils = Java.use("org.webrtc.voiceengine.WebRtcAudioUtils")
        WebRtcAudioUtils.runningOnEmulator.overload().implementation = function(){
            return false;
        }

    function getRndInt(min,max) {
        return Math.floor(Math.random()*(max-min))+min;
    }
    var android_id = getRndInt(0x107118522d7fe0,0x507cc8522d7fe0);
    android_id = android_id.toString(16);

        var Secure = Java.use("android.provider.Settings$Secure");
        Secure.getString.implementation = function (contxt,strr) {
            if(strr.indexOf("android_id")>-1) {
                    //console.log("real Android_ID: "+this.getString(contxt,strr));
                    return android_id;
            } else {
                    return this.getString(contxt,strr);
            }
        }
});

""")

def on_message(message, data):
    type = message["type"]
    msg = message
    if type == "send":
        msg = message["payload"]
    elif type == 'error':
        msg = message['stack']    
    print(msg)  

script.on('message', on_message) 
script.load()
script1.load()
#device.resume(pid)
sys.stdin.read()