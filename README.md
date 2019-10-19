logs love live all stars (SIFAS) HTTP traffic through a stub library

architecture is ARM only, as the game only ships with ARM binaries

this is updated as of 2019-10-19. any update that changes the native binary
will require me to update it, so be patient if it breaks, or read my
[notes](https://github.com/Francesco149/reversing-sifas) to learn how I
reversed it and how to update it yourself. eventually I will make it
dynamically find the functions, I wrote this in a rush and it gets the job
done for now

# building (linux)
download the latest android ndk standalone and extract it somewhere

set CC to your ndk location like so and run build.sh

```sh
export CC=~/android-ndk-r20/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang
./build.sh
```

# usage
have a rooted device with magisk hide enabled for lovelive connected over
adb, or just ssh into it

replace the original library

```sh
adb root
adb push libKLab.NativeInput.Native.so /data/app/
adb shell

cd /data/app/com.klab.lovelive.allstars-*/lib/arm/
mv libKLab.NativeInput.Native.so{,.bak}
mv /data/app/libKLab.NativeInput.Native.so .
chmod 755 libKLab.NativeInput.Native.so
chown system:system libKLab.NativeInput.Native.so
exit
```

clear logcat and start logging

```sh
adb shell logcat -c`
adb shell logcat | grep sniffas
```

now start the game and watch the log. I usually pipe the above command into
a file, like `adb shell logcat -d | grep sniffas > log.txt` so you can read
it in your favorite editor

my personal setup is a bit different, I host the binary on a local http
server and then adb shell over lan into my android machine, and wget it
as root:

```sh
adb shell
su
logcat -c
cd /data/app/com.klab.lovelive.allstars-*/lib/arm
wget -O libKLab.NativeInput.Native.so 192.168.1.2:8080
chmod 755 libKLab.NativeInput.Native.so
chown system:system libKLab.NativeInput.Native.so
am force-stop com.klab.lovelive.allstars
am start com.klab.lovelive.allstars/.MainActivity
logcat | grep sniffas
```
