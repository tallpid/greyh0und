This repo provides an example of fuzzing close-source JNI libraries on Android using AFL++ and Frida. You can find additional details in article [On Closed-Source JNI Fuzzing]().

The approach is based on the work by Quarkslab, which can be found in their blog post: [Android greybox fuzzing with AFL++ Frida mode](https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html).

To build the fuzzing harness, you can use the provided `CMakeLists.txt` files for both target libraries. The build process is straightforward and can be done using CMake and Make as following:

```bash

$ mkdir build && cd build
$ cmake -DANDROID_PLATFORM=27 \
        -DCMAKE_TOOLCHAIN_FILE=/path/to/your/android-ndk/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=arm64-v8a ..
$ make
```