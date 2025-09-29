#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <android/log.h>

#include "jenv.h"
#include "fuzz.h"

// Android-specific function declarations
#ifdef __ANDROID__
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#else
// For non-Android systems, provide a fallback
#define gettid() 0
#endif


#define BUF_LEN 10240
#define MAX_FUZZING_FUNCTION_ID 5

// Signal chain implementation to satisfy libsigchain
// Note: We only need stub implementations for fuzzing

static JavaCTX ctx;

//#define FUZZ_MODE

// Target BLEJniLib functions from com.thingclips.ble.jni.BLEJniLib
extern jint Java_com_thingclips_ble_jni_BLEJniLib_getCommandRequestData(JNIEnv*, jclass,
                                                           jint, jintArray,
                                                           jintArray, jintArray,
                                                           jobjectArray, jbyteArray);

extern jint Java_com_thingclips_ble_jni_BLEJniLib_parseKLVData(JNIEnv*, jclass,
                               jbyteArray, jint,
                               jbyte, jbyteArray);

extern jint Java_com_thingclips_ble_jni_BLEJniLib_madeSessionKey(JNIEnv*, jclass,
                               jbyteArray, jboolean,
                               jbyteArray);

extern jint Java_com_thingclips_ble_jni_BLEJniLib_getNormalRequestData(JNIEnv*, jclass,
                               jint, jbyteArray,
                               jint, jobjectArray);

extern jint Java_com_thingclips_ble_jni_BLEJniLib_parseDataRecived(JNIEnv*, jclass,
                                                           jbyteArray, jint, jbyteArray);

uint32_t get_random_shift(uint32_t min_val, uint32_t max_val) {
  if (min_val >= max_val) return 0;

  uint32_t range = max_val - min_val;
  uint32_t random_value = (uint32_t)random() % range;
  return min_val + random_value;
}

uint8_t** split_buffer(const uint8_t* buffer, size_t length, size_t num_chunks, uint32_t* out_chunk_size) {
  if (num_chunks == 0 || length == 0) return NULL;

  size_t average_chunk_size = length / num_chunks;
  uint8_t** chunks = malloc(num_chunks * sizeof(uint8_t*));
  if (!chunks) return NULL;

  size_t chunk_cursor = 0;
  for (size_t i = 0; i < num_chunks; i++) {
    if (chunk_cursor >= length) {
      chunks[i] = NULL; // No more data to chunk
      out_chunk_size[i] = 0;
      continue;
    }

    // TBD: Questionable logic, need adjust
    uint32_t chunk_size = average_chunk_size + get_random_shift(0, average_chunk_size / 2); 
    if (chunk_cursor + chunk_size > length) {
      chunk_size = length - chunk_cursor;
    }
    
    chunks[i] = malloc(chunk_size);
    if (!chunks[i]) {
      for (size_t j = 0; j < i; j++) {
        free(chunks[j]);
      }
      free(chunks);
      return NULL;
    }
    memcpy(chunks[i], buffer + chunk_cursor, chunk_size);
    out_chunk_size[i] = chunk_size;

    chunk_cursor += chunk_size;
  }

  return chunks;
}

void free_chunks(uint8_t** chunks, size_t num_chunks) {
  if (!chunks) return;
  for (size_t i = 0; i < num_chunks; i++) {
    free(chunks[i]);
  }
  free(chunks);
}


void fuzzing_print(const char* format, ...) {
  #ifdef FUZZ_MODE
    return;
  #endif

  va_list args;
  va_start(args, format);
  
  vfprintf(stderr, format, args);
  __android_log_vprint(ANDROID_LOG_DEBUG, "Fuzzing", format, args);
  
  va_end(args);
}

void hex_dump(const char* label, const void* data, size_t length) {
  #ifdef FUZZ_MODE
    return;
  #endif
  
  if (!data || length == 0) {
    fuzzing_print("%s: (null or empty)\n", label);
    return;
  }
  
  const uint8_t* bytes = (const uint8_t*)data;
  size_t limited_length = length > 256 ? 256 : length;
  fuzzing_print("%s (%zu bytes%s): ", label, length, length > 256 ? ", showing first 256" : "");
  
  for (size_t i = 0; i < limited_length; i++) {
    fprintf(stderr, "%02x ", bytes[i]);
    if ((i + 1) % 16 == 0) {
      fprintf(stderr, "\n                    ");
    }
  }
  fprintf(stderr, "\n");
}

void dump_jbytearray(JNIEnv* env, const char* label, jbyteArray array) {
  #ifdef FUZZ_MODE
    return;
  #endif
  
  if (!array) {
    fuzzing_print("%s: (null jbyteArray)\n", label);
    return;
  }
  
  jsize length = (*env)->GetArrayLength(env, array);
  if (length <= 0) {
    fuzzing_print("%s: (empty jbyteArray)\n", label);
    return;
  }
  
  jbyte* elements = (*env)->GetByteArrayElements(env, array, NULL);
  if (!elements) {
    fuzzing_print("%s: (failed to get array elements)\n", label);
    return;
  }
  
  jsize limited_length = length > 256 ? 256 : length;
  fuzzing_print("%s (%d bytes%s): ", label, length, length > 256 ? ", showing first 256" : "");
  for (jsize i = 0; i < limited_length; i++) {
    fprintf(stderr, "%02x ", (uint8_t)elements[i]);
    if ((i + 1) % 16 == 0) {
      fprintf(stderr, "\n                    ");
    }
  }
  fprintf(stderr, "\n");
  
  (*env)->ReleaseByteArrayElements(env, array, elements, JNI_ABORT);
}

void dump_jintarray(JNIEnv* env, const char* label, jintArray array) {
  #ifdef FUZZ_MODE
    return;
  #endif
  
  if (!array) {
    fuzzing_print("%s: (null jintArray)\n", label);
    return;
  }
  
  jsize length = (*env)->GetArrayLength(env, array);
  if (length <= 0) {
    fuzzing_print("%s: (empty jintArray)\n", label);
    return;
  }
  
  jint* elements = (*env)->GetIntArrayElements(env, array, NULL);
  if (!elements) {
    fuzzing_print("%s: (failed to get array elements)\n", label);
    return;
  }
  
  jsize limited_length = length > 64 ? 64 : length;
  fuzzing_print("%s (%d ints%s): ", label, length, length > 64 ? ", showing first 64" : "");
  for (jsize i = 0; i < limited_length; i++) {
    fprintf(stderr, "0x%08x ", elements[i]);
    if ((i + 1) % 8 == 0) {
      fprintf(stderr, "\n                    ");
    }
  }
  fprintf(stderr, "\n");
  
  (*env)->ReleaseIntArrayElements(env, array, elements, JNI_ABORT);
}

void dump_jobjectarray(JNIEnv* env, const char* label, jobjectArray array) {
  #ifdef FUZZ_MODE
    return;
  #endif
  
  if (!array) {
    fuzzing_print("%s: (null jobjectArray)\n", label);
    return;
  }
  
  jsize length = (*env)->GetArrayLength(env, array);
  if (length <= 0) {
    fuzzing_print("%s: (empty jobjectArray)\n", label);
    return;
  }
  
  fuzzing_print("%s (%d elements):\n", label, length);
  for (jsize i = 0; i < length; i++) {
    jobject element = (*env)->GetObjectArrayElement(env, array, i);
    if (!element) {
      fuzzing_print("  [%d]: (null element)\n", i);
    } else {
      jbyteArray byteArray = (jbyteArray)element;
      char element_label[64];
      snprintf(element_label, sizeof(element_label), "  [%d]", i);
      dump_jbytearray(env, element_label, byteArray);
      (*env)->DeleteLocalRef(env, element);
    }
  }
}


// Signal handler that prints detailed crash information (Android-compatible)
void crash_signal_handler(int sign) {
    fprintf(stderr, "\n[CRASH] Signal %d (%s) received!\n", sign, 
            sign == SIGSEGV ? "SIGSEGV" :
            sign == SIGABRT ? "SIGABRT" :
            sign == SIGILL ? "SIGILL" :
            sign == SIGBUS ? "SIGBUS" :
            sign == SIGFPE ? "SIGFPE" : "UNKNOWN");
    
    fprintf(stderr, "[CRASH] PID: %d, TID: %d\n", getpid(), (int)gettid());
    
    fprintf(stderr, "[CRASH] Terminating due to signal %d\n", sign);
    fflush(stderr);
    
    signal(sign, SIG_DFL);
    raise(sign);
    
    exit(128 + sign);
}

void install_crash_handlers(void) {
    signal(SIGSEGV, crash_signal_handler);
    signal(SIGABRT, crash_signal_handler);
    signal(SIGILL, crash_signal_handler);
    signal(SIGBUS, crash_signal_handler);
    signal(SIGFPE, crash_signal_handler);
    
    fprintf(stderr, "[DEBUG] Crash handlers installed for SIGSEGV, SIGABRT, SIGILL, SIGBUS, SIGFPE\n");
}

// Export the functions that libsigchain expects
__attribute__((visibility("default"))) 
void SetSpecialSignalHandlerFn(int sign, void* handler) {
    fuzzing_print("[+] SetSpecialSignalHandlerFn called for signal %d with handler %p\n", sign, handler);

    if (sign == SIGSEGV || sign == SIGABRT || sign == SIGILL || 
        sign == SIGBUS || sign == SIGFPE) {
        install_crash_handlers();
    }
}

__attribute__((visibility("default"))) 
void* GetSpecialSignalHandlerFn(int signal) {
    fuzzing_print("[+] GetSpecialSignalHandlerFn called for signal %d\n", signal);
    return NULL;
}

__attribute__((visibility("default"))) 
void EnsureFrontOfChain(int signal) {
    fuzzing_print("[+] EnsureFrontOfChain called for signal %d\n", signal);
    fprintf(stderr, "[libsigchain] Ensuring front of chain for signal %d\n", signal);
}

__attribute__((visibility("default"))) 
void InitializeSignalChain(void) {
    fuzzing_print("[+] InitializeSignalChain called\n");
    fprintf(stderr, "[libsigchain] Signal chain initialized\n");
    // Install crash handlers during initialization
    install_crash_handlers();
}

__attribute__((visibility("default"))) 
void AddSpecialSignalHandlerFn(int sign, void* handler) {
    fuzzing_print("[+] AddSpecialSignalHandlerFn called for signal %d with handler %p\n", sign, handler);
    fprintf(stderr, "[libsigchain] Adding special signal handler for signal %d\n", sign);
    
    // Install crash handlers for critical signals
    if (sign == SIGSEGV || sign == SIGABRT || sign == SIGILL || 
        sign == SIGBUS || sign == SIGFPE) {
        install_crash_handlers();
    }
}

__attribute__((visibility("default"))) 
void RemoveSpecialSignalHandlerFn(int signalID, void* handler) {
    fuzzing_print("[+] RemoveSpecialSignalHandlerFn called for signal %d with handler %p\n", signalID, handler);
    fprintf(stderr, "[libsigchain] Removing special signal handler for signal %d\n", signalID);
}


void getCommandRequestData(const uint8_t* buffer, size_t length) {
      fuzzing_print("Fuzzing function getCommandRequestData\n");
    uint32_t chunk_size[5] = {0};
    uint8_t **chunks = split_buffer(buffer + 1, length, 5, chunk_size);
    if (chunks == NULL) {
      fprintf(stderr, "Failed to split buffer into chunks\n");
      return;
    }

    fuzzing_print("=== Buffer Chunks for getCommandRequestData ===\n");
    for (int i = 0; i < 5; i++) {
      if (chunks[i] && chunk_size[i] > 0) {
        char chunk_label[32];
        snprintf(chunk_label, sizeof(chunk_label), "Chunk[%d]", i);
        hex_dump(chunk_label, chunks[i], chunk_size[i]);
      } else {
        fuzzing_print("Chunk[%d]: (null or empty)\n", i);
      }
    }
    fuzzing_print("=== End Buffer Chunks ===\n");

    jint firstArgCount = (chunks[0] && chunk_size[0] >= 4) ? chunk_size[0] / 4 : 0;
    jint actualFirstArgCount = firstArgCount > 0 ? firstArgCount : 1;
    jintArray jFirstArg = (*ctx.env)->NewIntArray(ctx.env, actualFirstArgCount);
    if (!jFirstArg || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to create jFirstArg array\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      free_chunks(chunks, 5);
      return;
    }
    if (firstArgCount > 0 && chunks[0] != NULL) {
      (*ctx.env)->SetIntArrayRegion(ctx.env, jFirstArg, 0, firstArgCount, (const jint*)chunks[0]);
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Exception occurred while setting jFirstArg data\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
        free_chunks(chunks, 5);
        return;
      }
    }
    fuzzing_print("\t jFirstArg length == %d\n", firstArgCount);
    
    jint secondArgCount = (chunks[1] && chunk_size[1] >= 4) ? chunk_size[1] / 4 : 0;
    jint actualSecondArgCount = secondArgCount > 0 ? secondArgCount : 1;  // Ensure at least size 1
    jintArray jSecondArg = (*ctx.env)->NewIntArray(ctx.env, actualSecondArgCount);
    if (!jSecondArg || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to create jSecondArg array\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      free_chunks(chunks, 5);
      return;
    }
    if (secondArgCount > 0 && chunks[1] != NULL) {
      (*ctx.env)->SetIntArrayRegion(ctx.env, jSecondArg, 0, secondArgCount, (const jint*)chunks[1]);
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Exception occurred while setting jSecondArg data\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
        free_chunks(chunks, 5);
        return;
      }
    }
    fuzzing_print("\t jSecondArg length == %d\n", secondArgCount);

    jint thirdArgCount = (chunks[2] && chunk_size[2] >= 4) ? chunk_size[2] / 4 : 0;
    jint actualThirdArgCount = thirdArgCount > 0 ? thirdArgCount : 1;
    jintArray jThirdArg = (*ctx.env)->NewIntArray(ctx.env, actualThirdArgCount);
    if (!jThirdArg || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to create jThirdArg array\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
      free_chunks(chunks, 5);
      return;
    }
    if (thirdArgCount > 0 && chunks[2] != NULL) {
      (*ctx.env)->SetIntArrayRegion(ctx.env, jThirdArg, 0, thirdArgCount, (const jint*)chunks[2]);
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Exception occurred while setting jThirdArg data\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
        free_chunks(chunks, 5);
        return;
      }
    }
    fuzzing_print("\t jThirdArg length == %d\n", thirdArgCount);

    jint fourthArgCount = (chunks[3] && chunk_size[3] >= 4) ? chunk_size[3] / 4 : 0;
    jint actualFourthArgCount = fourthArgCount > 0 ? fourthArgCount : 1;
    
    jclass byteArrayClass = (*ctx.env)->FindClass(ctx.env, "[B");
    if (!byteArrayClass || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to find byte array class\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
      free_chunks(chunks, 5);
      return;
    }
    
    jobjectArray jFourthArg = (*ctx.env)->NewObjectArray(ctx.env, actualFourthArgCount, byteArrayClass, NULL);
    if (!jFourthArg || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to create jFourthArg array\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
      free_chunks(chunks, 5);
      return;
    }
    
    if (fourthArgCount > 0 && chunks[3] != NULL) {
      size_t bytes_per_element = chunk_size[3] / actualFourthArgCount;
      if (bytes_per_element == 0) bytes_per_element = 1;
      
      for (jint i = 0; i < actualFourthArgCount; i++) {
        size_t start_offset = i * bytes_per_element;
        size_t element_size = bytes_per_element;
        
        if (start_offset >= chunk_size[3]) {
          element_size = 1;
          jbyteArray subArray = (*ctx.env)->NewByteArray(ctx.env, 1);
          if (!subArray || (*ctx.env)->ExceptionCheck(ctx.env)) {
            fuzzing_print("ERROR: Failed to create subArray at index %d\n", i);
            if ((*ctx.env)->ExceptionCheck(ctx.env)) {
              (*ctx.env)->ExceptionDescribe(ctx.env);
              (*ctx.env)->ExceptionClear(ctx.env);
            }
            // Create a minimal fallback array
            subArray = (*ctx.env)->NewByteArray(ctx.env, 1);
          }
          if (subArray) {
            (*ctx.env)->SetObjectArrayElement(ctx.env, jFourthArg, i, subArray);
            if ((*ctx.env)->ExceptionCheck(ctx.env)) {
              (*ctx.env)->ExceptionDescribe(ctx.env);
              (*ctx.env)->ExceptionClear(ctx.env);
            }
            (*ctx.env)->DeleteLocalRef(ctx.env, subArray);
          }
        } else {
          if (start_offset + element_size > chunk_size[3]) {
            element_size = chunk_size[3] - start_offset;
          }
          
          jbyteArray subArray = (*ctx.env)->NewByteArray(ctx.env, element_size);
          if (!subArray || (*ctx.env)->ExceptionCheck(ctx.env)) {
            fuzzing_print("ERROR: Failed to create subArray at index %d with size %zu\n", i, element_size);
            if ((*ctx.env)->ExceptionCheck(ctx.env)) {
              (*ctx.env)->ExceptionDescribe(ctx.env);
              (*ctx.env)->ExceptionClear(ctx.env);
            }
            // Create a minimal fallback array
            subArray = (*ctx.env)->NewByteArray(ctx.env, 1);
          }
          if (subArray) {
            if (element_size > 0 && start_offset < chunk_size[3]) {
              (*ctx.env)->SetByteArrayRegion(ctx.env, subArray, 0, element_size,
                                           (const jbyte*)(chunks[3] + start_offset));
              if ((*ctx.env)->ExceptionCheck(ctx.env)) {
                (*ctx.env)->ExceptionDescribe(ctx.env);
                (*ctx.env)->ExceptionClear(ctx.env);
              }
            }
            (*ctx.env)->SetObjectArrayElement(ctx.env, jFourthArg, i, subArray);
            if ((*ctx.env)->ExceptionCheck(ctx.env)) {
              (*ctx.env)->ExceptionDescribe(ctx.env);
              (*ctx.env)->ExceptionClear(ctx.env);
            }
            (*ctx.env)->DeleteLocalRef(ctx.env, subArray);
          }
        }
      }
    } else {
      // Fill with empty byte arrays
      for (jint i = 0; i < actualFourthArgCount; i++) {
        jbyteArray emptyArray = (*ctx.env)->NewByteArray(ctx.env, 1);
        if (!emptyArray || (*ctx.env)->ExceptionCheck(ctx.env)) {
          fuzzing_print("ERROR: Failed to create emptyArray at index %d\n", i);
          if ((*ctx.env)->ExceptionCheck(ctx.env)) {
            (*ctx.env)->ExceptionDescribe(ctx.env);
            (*ctx.env)->ExceptionClear(ctx.env);
          }
          // Try again with a minimal array
          emptyArray = (*ctx.env)->NewByteArray(ctx.env, 1);
        }
        if (emptyArray) {
          (*ctx.env)->SetObjectArrayElement(ctx.env, jFourthArg, i, emptyArray);
          if ((*ctx.env)->ExceptionCheck(ctx.env)) {
            (*ctx.env)->ExceptionDescribe(ctx.env);
            (*ctx.env)->ExceptionClear(ctx.env);
          }
          (*ctx.env)->DeleteLocalRef(ctx.env, emptyArray);
        } else {
          fuzzing_print("ERROR: Could not create any array for index %d, this will leave a NULL element\n", i);
        }
      }
    }
    
    // Verify that all elements in the array are non-NULL
    for (jint i = 0; i < actualFourthArgCount; i++) {
      jobject element = (*ctx.env)->GetObjectArrayElement(ctx.env, jFourthArg, i);
      if (!element) {
        fuzzing_print("WARNING: Element at index %d is NULL, creating emergency replacement\n", i);
        jbyteArray emergencyArray = (*ctx.env)->NewByteArray(ctx.env, 1);
        if (emergencyArray) {
          (*ctx.env)->SetObjectArrayElement(ctx.env, jFourthArg, i, emergencyArray);
          (*ctx.env)->DeleteLocalRef(ctx.env, emergencyArray);
        }
      } else {
        (*ctx.env)->DeleteLocalRef(ctx.env, element);
      }
    }
    fuzzing_print("\t jFourthArg length == %d\n", fourthArgCount);

    jint fifthArgCount = chunks[4] ? chunk_size[4] : 0;
    jint actualFifthArgCount = 65536;  // Always use large buffer size for output
    jbyteArray jFifthArg = (*ctx.env)->NewByteArray(ctx.env, fifthArgCount);
    if (!jFifthArg || (*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: Failed to create jFifthArg array\n");
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
      (*ctx.env)->DeleteLocalRef(ctx.env, jFourthArg);
      free_chunks(chunks, 5);
      return;
    }
    if (fifthArgCount > 0 && chunks[4] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jFifthArg, 0, fifthArgCount,
                                     (const jbyte*)chunks[4]);
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Exception occurred while setting jFifthArg data\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFourthArg);
        (*ctx.env)->DeleteLocalRef(ctx.env, jFifthArg);
        free_chunks(chunks, 5);
        return;
      }
    }
    fuzzing_print("\t jFifthArg length == %d, actual size == %d (fixed large buffer)\n", fifthArgCount, fifthArgCount);


    /*
    Java_com_thingclips_ble_jni_BLEJniLib_getCommandRequestData(JNIEnv*, jclass,
                                                           jint, jintArray,
                                                           jintArray, jintArray,
                                                           jobjectArray, jbyteArray)
                                                           */

    // Additional safety checks before calling the native function
    if (!jFirstArg || !jSecondArg || !jThirdArg || !jFourthArg || !jFifthArg) {
      fuzzing_print("ERROR: One or more arrays is NULL before calling native function\n");
      fuzzing_print("  jFirstArg: %p, jSecondArg: %p, jThirdArg: %p, jFourthArg: %p, jFifthArg: %p\n",
                   jFirstArg, jSecondArg, jThirdArg, jFourthArg, jFifthArg);
      // Clean up and return
      if (jFirstArg) (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
      if (jSecondArg) (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
      if (jThirdArg) (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
      if (jFourthArg) (*ctx.env)->DeleteLocalRef(ctx.env, jFourthArg);
      if (jFifthArg) (*ctx.env)->DeleteLocalRef(ctx.env, jFifthArg);
      free_chunks(chunks, 5);
      return;
    }

    fuzzing_print("About to call getCommandRequestData with arrays: jFirstArg=%p, jSecondArg=%p, jThirdArg=%p, jFourthArg=%p, jFifthArg=%p\n",
                 jFirstArg, jSecondArg, jThirdArg, jFourthArg, jFifthArg);

    // Dump input arrays content in hex
    fuzzing_print("=== Input Arrays Hex Dump ===\n");
    dump_jintarray(ctx.env, "jFirstArg", jFirstArg);
    dump_jintarray(ctx.env, "jSecondArg", jSecondArg);
    dump_jintarray(ctx.env, "jThirdArg", jThirdArg);
    dump_jobjectarray(ctx.env, "jFourthArg", jFourthArg);
    dump_jbytearray(ctx.env, "jFifthArg", jFifthArg);
    fuzzing_print("=== End Hex Dump ===\n");

    jint result = Java_com_thingclips_ble_jni_BLEJniLib_getCommandRequestData(
        ctx.env, NULL, firstArgCount, jFirstArg, jSecondArg, jThirdArg, jFourthArg,
        jFifthArg);
    
    // Check for JNI exception after function call
    if ((*ctx.env)->ExceptionCheck(ctx.env)) {
      fuzzing_print("ERROR: JNI exception occurred during getCommandRequestData call\n");
          jthrowable exception = (*ctx.env)->ExceptionOccurred(ctx.env);
          if (exception != NULL) {
              // Clear the exception temporarily to call Java methods
              (*ctx.env)->ExceptionClear(ctx.env);
              
              // Get exception class and toString method
              jclass throwableClass = (*ctx.env)->GetObjectClass(ctx.env, exception);
              jmethodID toStringMethod = (*ctx.env)->GetMethodID(ctx.env, throwableClass, "toString", "()Ljava/lang/String;");
              
              if (toStringMethod != NULL) {
                  jstring exceptionString = (jstring)(*ctx.env)->CallObjectMethod(ctx.env, exception, toStringMethod);
                  if (exceptionString != NULL) {
                      const char* exceptionMsg = (*ctx.env)->GetStringUTFChars(ctx.env, exceptionString, NULL);
                      fuzzing_print("Exception details: %s\n", exceptionMsg);
                      (*ctx.env)->ReleaseStringUTFChars(ctx.env, exceptionString, exceptionMsg);
                  }
              }
              
              // Get and print stack trace
              jmethodID printStackTraceMethod = (*ctx.env)->GetMethodID(ctx.env, throwableClass, "printStackTrace", "()V");
              if (printStackTraceMethod != NULL) {
                  fuzzing_print("Java stack trace:\n");
                  (*ctx.env)->CallVoidMethod(ctx.env, exception, printStackTraceMethod);
              }
              
              // Clean up local references
              (*ctx.env)->DeleteLocalRef(ctx.env, throwableClass);
              (*ctx.env)->DeleteLocalRef(ctx.env, exception);
          } else {
              // Fallback to original method
              (*ctx.env)->ExceptionDescribe(ctx.env);
              (*ctx.env)->ExceptionClear(ctx.env);
          }
    } else {
      fuzzing_print("getCommandRequestData returned: %d\n", result);
    }
    
    (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg);
    (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg);
    (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg);
    (*ctx.env)->DeleteLocalRef(ctx.env, jFourthArg);
    (*ctx.env)->DeleteLocalRef(ctx.env, jFifthArg);

    // Clean up allocated chunks
    free_chunks(chunks, 5);
}

void fuzz_main(const uint8_t* buffer, size_t length) {
  // Java environment should already be initialized by main()
  if (ctx.env == NULL) {
    fuzzing_print("Java environment not initialized!\n");
    exit(1);
  }

  if (length < 5 || buffer == NULL) {
    fuzzing_print("Invalid buffer length or NULL buffer.\n");
    fprintf(stderr, "Buffer length: %zu\n", length);
    return;
  }

  uint8_t fuzzing_function_id = buffer[0] % MAX_FUZZING_FUNCTION_ID;
  length--;

  fuzzing_print("Buffer length: %zu, Fuzzing function ID: %d\n", length, fuzzing_function_id);

  // Dump the original input buffer in hex
  fuzzing_print("=== Original Input Buffer ===\n");
  hex_dump("Input Buffer", buffer, length + 1); // +1 to include the function ID byte
  fuzzing_print("Fuzzing Function ID: 0x%02x (%d)\n", buffer[0], fuzzing_function_id);
  fuzzing_print("=== End Input Buffer ===\n");

  switch (fuzzing_function_id) {
// getCommandRequestData
  case 0: {

    fuzzing_print("Fuzzing function getCommandRequestData\n");
    getCommandRequestData(buffer, length);
    break;
  }

  case 1: {
    fuzzing_print("Fuzzing function parseKLVData\n");
    if (length < 5) {
      fuzzing_print("Buffer length is too short for parseKLVData.\n");
      return;
    }

    jint arg1 = (jint)buffer[1];
    jbyte arg2 = (jbyte)buffer[2];
    uint32_t chunk_size_1[2] = {0};
    uint8_t **chunks_1 = split_buffer(buffer + 3, length - 3, 2, chunk_size_1);
    if (chunks_1 == NULL) {
      fuzzing_print("Failed to split buffer into chunks for parseKLVData.\n");
      return;
    }

    // Dump the chunks created from input buffer
    fuzzing_print("=== Buffer Chunks for parseKLVData ===\n");
    for (int i = 0; i < 2; i++) {
      if (chunks_1[i] && chunk_size_1[i] > 0) {
        char chunk_label[32];
        snprintf(chunk_label, sizeof(chunk_label), "Chunk_1[%d]", i);
        hex_dump(chunk_label, chunks_1[i], chunk_size_1[i]);
      } else {
        fuzzing_print("Chunk_1[%d]: (null or empty)\n", i);
      }
    }
    fuzzing_print("=== End Buffer Chunks ===\n");

    jint firstArgSize = chunks_1[0] ? chunk_size_1[0] : 0;
    jint actualFirstArgSize = firstArgSize > 0 ? firstArgSize : 1;
    jbyteArray jFirstArg_1 = (*ctx.env)->NewByteArray(ctx.env, actualFirstArgSize);
    if (firstArgSize > 0 && chunks_1[0] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jFirstArg_1, 0, firstArgSize,
                                     (const jbyte*)chunks_1[0]);
    }
    
    jint secondArgSize = chunks_1[1] ? chunk_size_1[1] : 0;
    jint actualSecondArgSize = secondArgSize > 0 ? secondArgSize : 1;
    jbyteArray jSecondArg_1 = (*ctx.env)->NewByteArray(ctx.env, actualSecondArgSize);
    if (secondArgSize > 0 && chunks_1[1] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jSecondArg_1, 0, secondArgSize,
                                     (const jbyte*)chunks_1[1]);
    }
                                   
    fuzzing_print("\t jFirstArg length == %d\n", firstArgSize);
    fuzzing_print("\t jSecondArg length == %d\n", secondArgSize);

    // Dump input parameters and arrays content in hex
    fuzzing_print("=== parseKLVData Input Parameters ===\n");
    fuzzing_print("arg1 (jint): 0x%08x (%d)\n", arg1, arg1);
    fuzzing_print("arg2 (jbyte): 0x%02x (%d)\n", (uint8_t)arg2, arg2);
    dump_jbytearray(ctx.env, "jFirstArg_1", jFirstArg_1);
    dump_jbytearray(ctx.env, "jSecondArg_1", jSecondArg_1);
    fuzzing_print("=== End parseKLVData Input ===\n");

    jint result_1 = Java_com_thingclips_ble_jni_BLEJniLib_parseKLVData(
        ctx.env, NULL, jFirstArg_1, arg1, arg2, jSecondArg_1);

    fuzzing_print("parseKLVData returned: %d\n", result_1);

    (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_1);
    (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg_1);
    // Clean up allocated chunks
    free_chunks(chunks_1, 2);
    break;
  }



  case 2: {
    fuzzing_print("Fuzzing function madeSessionKey\n");
    if (length < 5) {
      fuzzing_print("Buffer length is too short for madeSessionKey.\n");
      return;
    }

    jint arg1 = (jint)buffer[1];
    jboolean arg2 = (jboolean)buffer[2];
    uint32_t chunk_size_3[2] = {0};
    uint8_t **chunks_3 = split_buffer(buffer + 3, length - 3, 2, chunk_size_3);
    if (chunks_3 == NULL) {
      fuzzing_print("Failed to split buffer into chunks for madeSessionKey.\n");
      return;
    }

    // Dump the chunks created from input buffer
    fuzzing_print("=== Buffer Chunks for madeSessionKey ===\n");
    for (int i = 0; i < 2; i++) {
      if (chunks_3[i] && chunk_size_3[i] > 0) {
        char chunk_label[32];
        snprintf(chunk_label, sizeof(chunk_label), "Chunk_3[%d]", i);
        hex_dump(chunk_label, chunks_3[i], chunk_size_3[i]);
      } else {
        fuzzing_print("Chunk_3[%d]: (null or empty)\n", i);
      }
    }
    fuzzing_print("=== End Buffer Chunks ===\n");
    jint firstArgSize = chunks_3[0] ? chunk_size_3[0] : 0;
    jint actualFirstArgSize = firstArgSize > 0 ? firstArgSize : 1;
    jbyteArray jFirstArg_3 = (*ctx.env)->NewByteArray(ctx.env, actualFirstArgSize);
    if (firstArgSize > 0 && chunks_3[0] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jFirstArg_3, 0, firstArgSize,
                                     (const jbyte*)chunks_3[0]);
    }

    jint secondArgSize = chunks_3[1] ? chunk_size_3[1] : 0;
    jint actualSecondArgSize = secondArgSize > 0 ? secondArgSize : 1;
    jbyteArray jSecondArg_3 = (*ctx.env)->NewByteArray(ctx.env, actualSecondArgSize);
    if (secondArgSize > 0 && chunks_3[1] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jSecondArg_3, 0, secondArgSize,
                                     (const jbyte*)chunks_3[1]);
    }

    fuzzing_print("\t jFirstArg length == %d\n", firstArgSize);
    fuzzing_print("\t jSecondArg length == %d\n", secondArgSize);

    // Dump input parameters and arrays content in hex
    fuzzing_print("=== madeSessionKey Input Parameters ===\n");
    fuzzing_print("arg2 (jboolean): %s (%d)\n", arg2 ? "true" : "false", arg2);
    dump_jbytearray(ctx.env, "jFirstArg_3", jFirstArg_3);
    dump_jbytearray(ctx.env, "jSecondArg_3", jSecondArg_3);
    fuzzing_print("=== End madeSessionKey Input ===\n");

    jint result_3 = Java_com_thingclips_ble_jni_BLEJniLib_madeSessionKey(
        ctx.env, NULL, jFirstArg_3, arg2, jSecondArg_3);

    fuzzing_print("madeSessionKey returned: %d\n", result_3);

    (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_3);
    (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg_3);
    free_chunks(chunks_3, 2);
    break;
  }


  case 3: {
    /*
    fuzzing_print("Fuzzing function getNormalRequestData\n");
    if (length < 5) {
      fuzzing_print("Buffer length is too short for getNormalRequestData.\n");
      return;
    }


    {
      jint arg1 = (jint)buffer[1];
      unsigned int arg2 = (unsigned int)buffer[2];
      uint32_t chunk_size_4[2] = {0};
      uint8_t **chunks_4 = split_buffer(buffer + 3, length - 3, 2, chunk_size_4);
      if (chunks_4 == NULL) {
        fuzzing_print("Failed to split buffer into chunks for getNormalRequestData.\n");
        return;
      }

      jint firstArgSize = chunks_4[0] ? chunk_size_4[0] : 0;
      // Ensure we create at least a 1-byte array to avoid NULL array issues
      jint actualFirstArgSize = firstArgSize > 0 ? firstArgSize : 1;
      jbyteArray jFirstArg_4 = (*ctx.env)->NewByteArray(ctx.env, actualFirstArgSize);
      if (firstArgSize > 0 && chunks_4[0] != NULL) {
        (*ctx.env)->SetByteArrayRegion(ctx.env, jFirstArg_4, 0, firstArgSize,
                       (const jbyte*)chunks_4[0]);
      }

      jint secondArgSize = chunks_4[1] ? chunk_size_4[1] : 0;
      jint actualSecondArgSize = secondArgSize > 0 ? secondArgSize : 1;  // Ensure at least size 1
      
      // The native code expects an array of jbyteArray objects, not generic Objects
      // First, find the byte array class
      jclass byteArrayClass = (*ctx.env)->FindClass(ctx.env, "[B");
      if (!byteArrayClass || (*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Failed to find byte array class\n");
        if ((*ctx.env)->ExceptionCheck(ctx.env)) {
          (*ctx.env)->ExceptionDescribe(ctx.env);
          (*ctx.env)->ExceptionClear(ctx.env);
        }
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_4);
        free_chunks(chunks_4, 2);
        return;
      }
      
      // Create an array that can hold jbyteArray objects
      jobjectArray jSecondArg_4 = (*ctx.env)->NewObjectArray(ctx.env, actualSecondArgSize, byteArrayClass, NULL);
      if (!jSecondArg_4 || (*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: Failed to create jSecondArg_4 array\n");
        if ((*ctx.env)->ExceptionCheck(ctx.env)) {
          (*ctx.env)->ExceptionDescribe(ctx.env);
          (*ctx.env)->ExceptionClear(ctx.env);
        }
        (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_4);
        free_chunks(chunks_4, 2);
        return;
      }
      
      // Fill the array with valid jbyteArray objects to avoid NULL elements
      // The native function will call SetByteArrayRegion on each element
      for (jint i = 0; i < actualSecondArgSize; i++) {
        // Create byte arrays large enough to hold the data that getCommonRequestData will write
        // Based on the decompiled code, it writes (trsmitr_subpkg_len + 1) bytes
        // We'll create arrays with reasonable size (e.g., 256 bytes) to handle any data
        jbyteArray byteArrayElement = (*ctx.env)->NewByteArray(ctx.env, 256);
        if (!byteArrayElement || (*ctx.env)->ExceptionCheck(ctx.env)) {
          fuzzing_print("ERROR: Failed to create byteArrayElement at index %d\n", i);
          if ((*ctx.env)->ExceptionCheck(ctx.env)) {
            (*ctx.env)->ExceptionDescribe(ctx.env);
            (*ctx.env)->ExceptionClear(ctx.env);
          }
          // Try again with a smaller fallback
          byteArrayElement = (*ctx.env)->NewByteArray(ctx.env, 64);
        }
        if (byteArrayElement) {
          (*ctx.env)->SetObjectArrayElement(ctx.env, jSecondArg_4, i, byteArrayElement);
          if ((*ctx.env)->ExceptionCheck(ctx.env)) {
            fuzzing_print("ERROR: Failed to set array element at index %d\n", i);
            (*ctx.env)->ExceptionDescribe(ctx.env);
            (*ctx.env)->ExceptionClear(ctx.env);
          }
          (*ctx.env)->DeleteLocalRef(ctx.env, byteArrayElement);
        } else {
          fuzzing_print("ERROR: Could not create any array for index %d, this will leave a NULL element\n", i);
        }
      }

      fuzzing_print("\t jFirstArg length == %d\n", firstArgSize);
      fuzzing_print("\t jSecondArg length == %d (actual size: %d)\n", secondArgSize, actualSecondArgSize);

      // Additional safety checks before calling the native function
      if (!jFirstArg_4 || !jSecondArg_4) {
        fuzzing_print("ERROR: One or more arrays is NULL before calling getNormalRequestData\n");
        fuzzing_print("  jFirstArg_4: %p, jSecondArg_4: %p\n", jFirstArg_4, jSecondArg_4);
        // Clean up and return
        if (jFirstArg_4) (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_4);
        if (jSecondArg_4) (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg_4);
        free_chunks(chunks_4, 2);
        return;
      }

      fuzzing_print("About to call getNormalRequestData with arrays: jFirstArg_4=%p, jSecondArg_4=%p\n",
                   jFirstArg_4, jSecondArg_4);

      jint result_4 = Java_com_thingclips_ble_jni_BLEJniLib_getNormalRequestData(
        ctx.env, NULL, arg1, jFirstArg_4, arg2, jSecondArg_4);

      // Check for JNI exception after function call
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during getNormalRequestData call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("getNormalRequestData returned: %d\n", result_4);
      }

      (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_4);
      (*ctx.env)->DeleteLocalRef(ctx.env, jSecondArg_4);
      // Clean up allocated chunks
      free_chunks(chunks_4, 2);
      break;
    }
    */
  }
  default: {
    fuzzing_print("Fuzzing function parseDataRecived");  
    if (length < 4) {
      fuzzing_print("Buffer length is too short for parseDataRecived.\n");
      return;
    }

    jint arg2 = (jint)buffer[1];
    uint32_t chunk_size_2[2] = {0};
    uint8_t **chunks_2 = split_buffer(buffer + 2, length - 2, 2, chunk_size_2);
    if (chunks_2 == NULL) {
      fuzzing_print("Failed to split buffer into chunks for parseDataRecived.\n");
      return;
    }

    // Dump the chunks created from input buffer
    fuzzing_print("=== Buffer Chunks for parseDataRecived ===\n");
    for (int i = 0; i < 2; i++) {
      if (chunks_2[i] && chunk_size_2[i] > 0) {
        char chunk_label[32];
        snprintf(chunk_label, sizeof(chunk_label), "Chunk_2[%d]", i);
        hex_dump(chunk_label, chunks_2[i], chunk_size_2[i]);
      } else {
        fuzzing_print("Chunk_2[%d]: (null or empty)\n", i);
      }
    }
    fuzzing_print("=== End Buffer Chunks ===\n");

    jint firstArgSize = chunks_2[0] ? chunk_size_2[0] : 0;
    jint actualFirstArgSize = firstArgSize > 0 ? firstArgSize : 1;
    jbyteArray jFirstArg_2 = (*ctx.env)->NewByteArray(ctx.env, actualFirstArgSize);
    if (firstArgSize > 0 && chunks_2[0] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jFirstArg_2, 0, firstArgSize,
                                     (const jbyte*)chunks_2[0]);
    }
    
    jint thirdArgSize = chunks_2[1] ? chunk_size_2[1] : 0;
    jint actualThirdArgSize = thirdArgSize > 0 ? thirdArgSize : 1;
    jbyteArray jThirdArg_2 = (*ctx.env)->NewByteArray(ctx.env, actualThirdArgSize);
    if (thirdArgSize > 0 && chunks_2[1] != NULL) {
      (*ctx.env)->SetByteArrayRegion(ctx.env, jThirdArg_2, 0, thirdArgSize,
                                     (const jbyte*)chunks_2[1]);
    }
                                   
    fuzzing_print("\t jFirstArg length == %d\n", firstArgSize);
    fuzzing_print("\t jThirdArg length == %d\n", thirdArgSize);

    // Dump input parameters and arrays content in hex
    fuzzing_print("=== parseDataRecived Input Parameters ===\n");
    fuzzing_print("arg2 (jint): 0x%08x (%d)\n", arg2, arg2);
    dump_jbytearray(ctx.env, "jFirstArg_2", jFirstArg_2);
    dump_jbytearray(ctx.env, "jThirdArg_2", jThirdArg_2);
    fuzzing_print("=== End parseDataRecived Input ===\n");

    jint result_2 = Java_com_thingclips_ble_jni_BLEJniLib_parseDataRecived(
        ctx.env, NULL, jFirstArg_2, arg2, jThirdArg_2);
    
    fuzzing_print("parseDataRecived returned: %d\n", result_2);

    (*ctx.env)->DeleteLocalRef(ctx.env, jFirstArg_2);
    (*ctx.env)->DeleteLocalRef(ctx.env, jThirdArg_2);    
    
    free_chunks(chunks_2, 2);
    
    break;
  }
  }
}


int main(int argc, char** argv) {
  int status;
  const uint8_t buffer[BUF_LEN];
  
  char* options[] = {
    "-Djava.class.path=/data/local/tmp/mock.dex",
    "-XX:-OmitStackTraceInFastThrow", "-Xcheck:jni"
  };
  int num_options = sizeof(options) / sizeof(options[0]);

  fuzzing_print("[+] Initializing Java environment once at startup...\n");
  
  install_crash_handlers();
  
  if ((status = init_java_env(&ctx, options, num_options)) != 0) {
    fuzzing_print("Failed to initialize Java environment: %d\n", status);
    return status;
  }
  fuzzing_print("[+] Java environment initialized successfully!\n");

  #ifdef FUZZ_MODE
    ssize_t rlength = fread((void*)buffer, 1, BUF_LEN, stdin);
  #else
    if (argc < 2) {
      fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
      return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
      fuzzing_print("Failed to open input file");
      return 1;
    }

    ssize_t rlength = fread((void*)buffer, 1, BUF_LEN, file);
    fclose(file);    
  #endif
  
  if (rlength == -1) {
    fuzzing_print("Error reading input file: %s\n", strerror(errno));
    return errno;
  }

  // Call the fuzz function (this will be the persistent entry point for AFL)
  fuzz_main(buffer, rlength);

  return 0;
}
