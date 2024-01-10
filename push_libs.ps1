.\adb.exe kill-server
.\adb.exe start-server
.\adb.exe root
$libpath = -join((.\adb.exe shell "pm path com.snapchat.android | sed -E 's/^.*:(.*)\/.*$/\1/' | head -1"), "/lib/arm64")
.\adb.exe push libsnap2half_arm64.so $libpath
.\adb.exe push libsnap2half_x64.so $libpath
.\adb.exe push libscplugin.so $libpath
.\adb.exe shell chmod 755 $libpath/libsnap2half_arm64.so $libpath/libsnap2half_x64.so $libpath/libsnap2half_x64.so $libpath/libscplugin.so 
.\adb.exe shell chown system:system $libpath/libsnap2half_arm64.so $libpath/libsnap2half_x64.so $libpath/libsnap2half_x64.so $libpath/libscplugin.so
Read-Host "press enter to continue..."