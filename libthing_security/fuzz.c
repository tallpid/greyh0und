#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <stdint.h>

#include "include/jenv.h"
#include <unistd.h>
#include <android/log.h>
#include <link.h>

#define DEF_LIB "libthing_security.so"
#define BUF_LEN 10240
#define MAX_FUZZING_FUNCTION_ID 6

// Signal chain implementation to satisfy libsigchain
// Note: We only need stub implementations for fuzzing

static JavaCTX ctx;
static void* lib_handle = NULL;

// Target function addresses and signatures from libthing_security.so
// Address 0x00000000000145E0
typedef jbyteArray (*encryptPostData_t)(JNIEnv*, jclass, jstring);

// Address 0x00000000000151E8
typedef const char* (*decryptResponseData_t)(JNIEnv*, jclass, jstring, jstring);

// Address 0x0000000000013194
typedef jstring (*doCommandNative_t)(JNIEnv*, jclass, jlong, jint, jbyteArray, jbyteArray, jbyte);

// Address 0000000000014A4C
typedef jstring (*genKey_t)(JNIEnv*, jclass, jstring, jstring, jstring);

// Address 00000000000153AC
typedef jstring (*getChKey_t)(JNIEnv*, jclass, jlong, jbyteArray);

// Address 0x0000000000014744
typedef const char* (*getEncryptorKey_t)(JNIEnv*, jclass, jstring, jstring);
static encryptPostData_t encryptPostData_func = NULL;
static decryptResponseData_t decryptResponseData_func = NULL;
static doCommandNative_t doCommandNative_func = NULL;
static genKey_t genKey_func = NULL;
static getChKey_t getChKey_func = NULL;
static getEncryptorKey_t getEncryptorKey_func = NULL;


// Utility functions
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
      chunks[i] = NULL;
      out_chunk_size[i] = 0;
      continue;
    }

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

jstring create_jstring(JNIEnv* env, uint8_t *data, size_t length) {
  if (length == 0) {
    return (*env)->NewStringUTF(env, "");
  }

  char* str_data = malloc(length + 1);
  if (!str_data) {
    return NULL;
  }
  
  memcpy(str_data, data, length);
  str_data[length] = '\0';

  jstring result = (*env)->NewStringUTF(env, str_data);
  free(str_data);
  
  return result;
}

jbyteArray create_jbytearray(JNIEnv* env, uint8_t *data, size_t length) {
  if (length == 0) {
    return (*env)->NewByteArray(env, 0);
  }

  jbyteArray result = (*env)->NewByteArray(env, length);
  if (!result) {
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, result, 0, length, (const jbyte*)data);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->DeleteLocalRef(env, result);
    return NULL;
  }
  
  return result;
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

void print_hex_data(const char* label, const uint8_t* data, size_t length) {
  if (!data || length == 0) {
    fuzzing_print("%s: (null or empty)\n", label);
    return;
  }
  
  size_t print_length = length > 100 ? 100 : length;
  fuzzing_print("%s (%zu bytes): ", label, length);
  
  for (size_t i = 0; i < print_length; i++) {
    fprintf(stderr, "%02x", data[i]);
    if (i % 16 == 15) fprintf(stderr, "\n                    ");
    else if (i % 4 == 3) fprintf(stderr, " ");
  }
  if (length > 100) {
    fprintf(stderr, "... (truncated)");
  }
  fprintf(stderr, "\n");
}

void print_jstring_content(const char* label, JNIEnv* env, jstring jstr) {
  if (!jstr) {
    fuzzing_print("%s: (null jstring)\n", label);
    return;
  }
  
  const char* str = (*env)->GetStringUTFChars(env, jstr, NULL);
  if (str) {
    size_t len = strlen(str);
    size_t print_len = len > 100 ? 100 : len;
    fuzzing_print("%s (%zu chars): \"", label, len);
    
    for (size_t i = 0; i < print_len; i++) {
      if (str[i] >= 32 && str[i] <= 126) {
        fprintf(stderr, "%c", str[i]);
      } else {
        fprintf(stderr, "\\x%02x", (unsigned char)str[i]);
      }
    }
    if (len > 100) {
      fprintf(stderr, "... (truncated)");
    }
    fprintf(stderr, "\"\n");
    
    (*env)->ReleaseStringUTFChars(env, jstr, str);
  } else {
    fuzzing_print("%s: (failed to get string content)\n", label);
  }
}

void print_jbytearray_content(const char* label, JNIEnv* env, jbyteArray jarray) {
  if (!jarray) {
    fuzzing_print("%s: (null jbyteArray)\n", label);
    return;
  }
  
  jsize length = (*env)->GetArrayLength(env, jarray);
  jbyte* bytes = (*env)->GetByteArrayElements(env, jarray, NULL);
  
  if (bytes) {
    size_t print_length = length > 100 ? 100 : length;
    fuzzing_print("%s (%d bytes): ", label, length);
    
    for (int i = 0; i < print_length; i++) {
      fprintf(stderr, "%02x", (unsigned char)bytes[i]);
      if (i % 16 == 15) fprintf(stderr, "\n                    ");
      else if (i % 4 == 3) fprintf(stderr, " ");
    }
    if (length > 100) {
      fprintf(stderr, "... (truncated)");
    }
    fprintf(stderr, "\n");
    
    (*env)->ReleaseByteArrayElements(env, jarray, bytes, JNI_ABORT);
  } else {
    fuzzing_print("%s: (failed to get array content)\n", label);
  }
}

// Signal chain implementations (stubs for fuzzing)
__attribute__((visibility("default"))) 
void SetSpecialSignalHandlerFn(int signal, void* handler) {
    fuzzing_print("[+] SetSpecialSignalHandlerFn called for signal %d with handler %p\n", signal, handler);
}

__attribute__((visibility("default"))) 
void* GetSpecialSignalHandlerFn(int signal) {
    fuzzing_print("[+] GetSpecialSignalHandlerFn called for signal %d\n", signal);
    return NULL;
}

__attribute__((visibility("default"))) 
void EnsureFrontOfChain(int signal) {
    fuzzing_print("[+] EnsureFrontOfChain called for signal %d\n", signal);
}

__attribute__((visibility("default"))) 
void InitializeSignalChain(void) {
    fuzzing_print("[+] InitializeSignalChain called\n");
}

__attribute__((visibility("default"))) 
void AddSpecialSignalHandlerFn(int signal, void* handler) {
    fuzzing_print("[+] AddSpecialSignalHandlerFn called for signal %d with handler %p\n", signal, handler);
}

__attribute__((visibility("default"))) 
void RemoveSpecialSignalHandlerFn(int signal, void* handler) {
    fuzzing_print("[+] RemoveSpecialSignalHandlerFn called for signal %d with handler %p\n", signal, handler);
}

// Initialize function pointers by resolving addresses in the loaded library
static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data) {
  void **base_addr_ptr = (void**)data;
  
  if (info->dlpi_name && strstr(info->dlpi_name, DEF_LIB)) {
    *base_addr_ptr = (void*)info->dlpi_addr;
    return 1;
  }
  return 0;
}

void* get_library_base_address(const char* library_name) {
  void* base_addr = NULL;
  
  dl_iterate_phdr(dl_iterate_callback, &base_addr);
  
  if (!base_addr) {
    // Fallback: parse /proc/self/maps
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
      return NULL;
    }
    
    char line[1024];
    
    while (fgets(line, sizeof(line), fp)) {
      if (strstr(line, library_name)) {
        char* endptr;
        base_addr = (void*)strtoul(line, &endptr, 16);
        break;
      }
    }
    
    fclose(fp);
  }
  
  return base_addr;
}

int init_function_pointers() {
  lib_handle = dlopen(DEF_LIB, RTLD_LAZY);
  if (!lib_handle) {
    fuzzing_print("ERROR: Cannot load library: %s\n", dlerror());
    return -1;
  }

  void* base_addr = get_library_base_address(DEF_LIB);
  if (!base_addr) {
    fuzzing_print("ERROR: Cannot find library base address\n");
    dlclose(lib_handle);
    return -1;
  }
  
  fuzzing_print("[+] Library loaded at base address: %p\n", base_addr);

  // Resolve target function addresses
  encryptPostData_func = (encryptPostData_t)((char*)base_addr + 0x145E0);
  fuzzing_print("[+] encryptPostData function resolved at: %p\n", encryptPostData_func);

  decryptResponseData_func = (decryptResponseData_t)((char*)base_addr + 0x151E8);
  fuzzing_print("[+] decryptResponseData function resolved at: %p\n", decryptResponseData_func);

  doCommandNative_func = (doCommandNative_t)((char*)base_addr + 0x13194);
  fuzzing_print("[+] doCommandNative function resolved at: %p\n", doCommandNative_func);

  genKey_func = (genKey_t)((char*)base_addr + 0x14A4C);
  fuzzing_print("[+] genKey function resolved at: %p\n", genKey_func);

  getChKey_func = (getChKey_t)((char*)base_addr + 0x153AC);
  fuzzing_print("[+] getChKey function resolved at: %p\n", getChKey_func);

  getEncryptorKey_func = (getEncryptorKey_t)((char*)base_addr + 0x14744);
  fuzzing_print("[+] getEncryptorKey function resolved at: %p\n", getEncryptorKey_func);

  return 0;
}

// Configure mock AssetManager with fuzz data
int configure_mock_asset_manager(const uint8_t* fuzz_data, size_t fuzz_size) {
  if (!ctx.env) {
    fuzzing_print("ERROR: Java environment not initialized\n");
    return -1;
  }

  jclass assetManagerClass = (*ctx.env)->FindClass(ctx.env, "mock/content/res/AssetManager");
  if (!assetManagerClass) {
    fuzzing_print("ERROR: Could not find mock AssetManager class\n");
    (*ctx.env)->ExceptionClear(ctx.env);
    return -1;
  }

  jmethodID setFuzzDataMethod = (*ctx.env)->GetStaticMethodID(ctx.env, assetManagerClass, 
                                                             "setFuzzAssetData", "([B)V");
  if (!setFuzzDataMethod) {
    fuzzing_print("ERROR: Could not find setFuzzAssetData method\n");
    (*ctx.env)->ExceptionClear(ctx.env);
    return -1;
  }

  jbyteArray fuzzArray = (*ctx.env)->NewByteArray(ctx.env, fuzz_size);
  if (!fuzzArray) {
    fuzzing_print("ERROR: Could not create byte array for fuzz data\n");
    return -1;
  }

  (*ctx.env)->SetByteArrayRegion(ctx.env, fuzzArray, 0, fuzz_size, (const jbyte*)fuzz_data);

  (*ctx.env)->CallStaticVoidMethod(ctx.env, assetManagerClass, setFuzzDataMethod, fuzzArray);

  if ((*ctx.env)->ExceptionCheck(ctx.env)) {
    fuzzing_print("ERROR: Exception calling setFuzzAssetData\n");
    (*ctx.env)->ExceptionDescribe(ctx.env);
    (*ctx.env)->ExceptionClear(ctx.env);
    return -1;
  }

  (*ctx.env)->DeleteLocalRef(ctx.env, fuzzArray);
  (*ctx.env)->DeleteLocalRef(ctx.env, assetManagerClass);

  fuzzing_print("[+] Mock AssetManager configured with %zu bytes of fuzz data\n", fuzz_size);
  return 0;
}

void fuzz_main(const uint8_t* buffer, size_t length) {
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

  if (configure_mock_asset_manager(buffer + 1, length) != 0) {
    fuzzing_print("WARNING: Failed to configure mock AssetManager\n");
  }

  switch (fuzzing_function_id) {
    // Fuzz encryptPostData function
    case 0: {
      fuzzing_print("Fuzzing function encryptPostData (address 0x145E0)\n");
      
      if (!encryptPostData_func) {
        fuzzing_print("ERROR: encryptPostData function not initialized\n");
        return;
      }

      jstring input_string = NULL;
      if (length > 0) {
        char* str_data = malloc(length + 1);
        if (!str_data) {
          fuzzing_print("ERROR: Failed to allocate memory for string data\n");
          return;
        }
        memcpy(str_data, buffer + 1, length);
        str_data[length] = '\0';
        
        input_string = (*ctx.env)->NewStringUTF(ctx.env, str_data);
        free(str_data);
        
        if (!input_string || (*ctx.env)->ExceptionCheck(ctx.env)) {
          fuzzing_print("ERROR: Failed to create Java string\n");
          if ((*ctx.env)->ExceptionCheck(ctx.env)) {
            (*ctx.env)->ExceptionDescribe(ctx.env);
            (*ctx.env)->ExceptionClear(ctx.env);
          }
          return;
        }
      } else {
        input_string = (*ctx.env)->NewStringUTF(ctx.env, "");
      }

      fuzzing_print("=== encryptPostData Arguments ===\n");
      print_jstring_content("arg1 (jstring)", ctx.env, input_string);
      fuzzing_print("About to call encryptPostData with string length: %zu\n", length);
      
      jbyteArray result = encryptPostData_func(ctx.env, NULL, input_string);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during encryptPostData call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("encryptPostData returned: %p\n", result);
        
        if (result) {
          jsize result_length = (*ctx.env)->GetArrayLength(ctx.env, result);
          fuzzing_print("Result array length: %d\n", result_length);
          print_jbytearray_content("Result", ctx.env, result);
          (*ctx.env)->DeleteLocalRef(ctx.env, result);
        }
      }

      if (input_string) {
        (*ctx.env)->DeleteLocalRef(ctx.env, input_string);
      }
      
      break;
    }

    case 1: {
      fuzzing_print("Fuzzing function decryptResponseData (address 0x151E8)\n");
      
      if (!decryptResponseData_func) {
        fuzzing_print("ERROR: decryptResponseData function not initialized\n");
        return;
      }

      uint32_t chunk_size[2] = {0};
      uint8_t **chunks = split_buffer(buffer + 1, length, 2, chunk_size);
      if (!chunks) {
        fuzzing_print("ERROR: Failed to split buffer for decryptResponseData\n");
        return;
      }

      jstring arg1 = create_jstring(ctx.env, chunks[0], chunk_size[0]);
      jstring arg2 = create_jstring(ctx.env, chunks[1], chunk_size[1]);

      if (!arg1 || !arg2) {
        fuzzing_print("ERROR: Failed to create jstring arguments\n");
        if (arg1) (*ctx.env)->DeleteLocalRef(ctx.env, arg1);
        if (arg2) (*ctx.env)->DeleteLocalRef(ctx.env, arg2);
        free_chunks(chunks, 2);
        return;
      }

      fuzzing_print("=== decryptResponseData Arguments ===\n");
      print_hex_data("chunk0 (raw)", chunks[0], chunk_size[0]);
      print_hex_data("chunk1 (raw)", chunks[1], chunk_size[1]);
      print_jstring_content("arg1 (jstring)", ctx.env, arg1);
      print_jstring_content("arg2 (jstring)", ctx.env, arg2);
      
      const char* result = decryptResponseData_func(ctx.env, NULL, arg1, arg2);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during decryptResponseData call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("decryptResponseData returned: %p\n", result);
        if (result) {
          size_t result_len = strlen(result);
          print_hex_data("Result (const char*)", (const uint8_t*)result, result_len);
        }
      }

      (*ctx.env)->DeleteLocalRef(ctx.env, arg1);
      (*ctx.env)->DeleteLocalRef(ctx.env, arg2);
      free_chunks(chunks, 2);
      break;
    }

    case 2: {
      fuzzing_print("Fuzzing function doCommandNative (address 0x13194)\n");
      
      if (!doCommandNative_func) {
        fuzzing_print("ERROR: doCommandNative function not initialized\n");
        return;
      }

      uint32_t chunk_size[4] = {0};
      uint8_t **chunks = split_buffer(buffer + 1, length, 4, chunk_size);
      if (!chunks) {
        fuzzing_print("ERROR: Failed to split buffer for doCommandNative\n");
        return;
      }

      // The jlong parameter expects a Context object with getPackageManager() method
      jlong long_arg = 0;
      jobject context_obj = NULL;
      
      if (length > 0) {
        jclass contextClass = (*ctx.env)->FindClass(ctx.env, "mock/content/Context");
        if (contextClass) {
          jmethodID constructor = (*ctx.env)->GetMethodID(ctx.env, contextClass, "<init>", "()V");
          if (constructor) {
            jobject contextObject = (*ctx.env)->NewObject(ctx.env, contextClass, constructor);
            if (contextObject) {
              context_obj = (*ctx.env)->NewGlobalRef(ctx.env, contextObject);
              if (context_obj) {
                long_arg = (jlong)context_obj;
                fuzzing_print("Created concrete Context object for jlong parameter\n");
              }
              (*ctx.env)->DeleteLocalRef(ctx.env, contextObject);
            }
          }
          (*ctx.env)->DeleteLocalRef(ctx.env, contextClass);
        }
        
        if (long_arg == 0) {
          fuzzing_print("Context creation failed, using NULL\n");
          long_arg = 0;
        }
      }

      jint int_arg = 0;
      if (chunk_size[0] >= sizeof(jint)) {
        memcpy(&int_arg, chunks[0], sizeof(jint));
      }

      jbyteArray byte_arg1 = create_jbytearray(ctx.env, chunks[1], chunk_size[1]);
      jbyteArray byte_arg2 = create_jbytearray(ctx.env, chunks[2], chunk_size[2]);

      jbyte byte_arg = 0;
      if (chunk_size[3] >= sizeof(jbyte)) {
        byte_arg = (jbyte)chunks[3][0];
      }

      if (!byte_arg1 || !byte_arg2) {
        fuzzing_print("ERROR: Failed to create jbyteArray arguments\n");
        if (byte_arg1) (*ctx.env)->DeleteLocalRef(ctx.env, byte_arg1);
        if (byte_arg2) (*ctx.env)->DeleteLocalRef(ctx.env, byte_arg2);
        if (context_obj) (*ctx.env)->DeleteGlobalRef(ctx.env, context_obj);
        free_chunks(chunks, 4);
        return;
      }

      fuzzing_print("=== doCommandNative Arguments ===\n");
      fuzzing_print("arg1 (jlong): 0x%016llx (%lld) [%s]\n", 
                   (unsigned long long)long_arg, (long long)long_arg,
                   context_obj ? "Context object" : "numeric value");
      fuzzing_print("arg2 (jint): 0x%08x (%d)\n", (unsigned int)int_arg, int_arg);
      print_jbytearray_content("arg3 (jbyteArray)", ctx.env, byte_arg1);
      print_jbytearray_content("arg4 (jbyteArray)", ctx.env, byte_arg2);
      fuzzing_print("arg5 (jbyte): 0x%02x (%d)\n", (unsigned char)byte_arg, byte_arg);

      fuzzing_print("Press Enter to continue..."); getchar(); // Wait for hooks ...
      
      if (context_obj) {
        fuzzing_print("Verifying Context object before function call...\n");
        jclass objClass = (*ctx.env)->GetObjectClass(ctx.env, context_obj);
        if (objClass) {
          fuzzing_print("Context object class retrieved successfully\n");
          (*ctx.env)->DeleteLocalRef(ctx.env, objClass);
        } else {
          fuzzing_print("ERROR: Failed to get object class for Context\n");
        }
      }

      jstring result = doCommandNative_func(ctx.env, NULL, long_arg, int_arg, byte_arg1, byte_arg2, byte_arg);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during doCommandNative call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("doCommandNative returned: %p\n", result);
        if (result) {
          print_jstring_content("Result (jstring)", ctx.env, result);
          (*ctx.env)->DeleteLocalRef(ctx.env, result);
        }
      }

      if (context_obj) {
        (*ctx.env)->DeleteGlobalRef(ctx.env, context_obj);
      }
      (*ctx.env)->DeleteLocalRef(ctx.env, byte_arg1);
      (*ctx.env)->DeleteLocalRef(ctx.env, byte_arg2);
      free_chunks(chunks, 4);
      break;
    }

    case 3: {
      fuzzing_print("Fuzzing function genKey (address 0x14A4C)\n");
      
      if (!genKey_func) {
        fuzzing_print("ERROR: genKey function not initialized\n");
        return;
      }

      uint32_t chunk_size[3] = {0};
      uint8_t **chunks = split_buffer(buffer + 1, length, 3, chunk_size);
      if (!chunks) {
        fuzzing_print("ERROR: Failed to split buffer for genKey\n");
        return;
      }

      void* void_arg = (chunk_size[0] > 0) ? chunks[0] : NULL;
      
      jstring str_arg1 = create_jstring(ctx.env, chunks[1], chunk_size[1]);
      jstring str_arg2 = create_jstring(ctx.env, chunks[2], chunk_size[2]);

      if (!str_arg1 || !str_arg2) {
        fuzzing_print("ERROR: Failed to create jstring arguments\n");
        if (str_arg1) (*ctx.env)->DeleteLocalRef(ctx.env, str_arg1);
        if (str_arg2) (*ctx.env)->DeleteLocalRef(ctx.env, str_arg2);
        free_chunks(chunks, 3);
        return;
      }

      fuzzing_print("=== genKey Arguments ===\n");
      fuzzing_print("arg1 (void*): %p\n", void_arg);
      print_hex_data("arg1 (void* content)", (const uint8_t*)void_arg, chunk_size[0]);
      print_jstring_content("arg2 (jstring)", ctx.env, str_arg1);
      print_jstring_content("arg3 (jstring)", ctx.env, str_arg2);

      jstring result = genKey_func(ctx.env, NULL, void_arg, str_arg1, str_arg2);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during genKey call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("genKey returned: %p\n", result);
        if (result) {
          print_jstring_content("Result", ctx.env, result);
          (*ctx.env)->DeleteLocalRef(ctx.env, result);
        }
      }

      (*ctx.env)->DeleteLocalRef(ctx.env, str_arg1);
      (*ctx.env)->DeleteLocalRef(ctx.env, str_arg2);
      free_chunks(chunks, 3);
      break;
    }

    case 4: {
      fuzzing_print("Fuzzing function getChKey (address 0x153AC)\n");
      
      if (!getChKey_func) {
        fuzzing_print("ERROR: getChKey function not initialized\n");
        return;
      }

      uint32_t chunk_size[2] = {0};
      uint8_t **chunks = split_buffer(buffer + 1, length, 2, chunk_size);
      if (!chunks) {
        fuzzing_print("ERROR: Failed to split buffer for getChKey\n");
        return;
      }

      jlong long_arg = 0;
      if (chunk_size[0] >= sizeof(jlong)) {
        memcpy(&long_arg, chunks[0], sizeof(jlong));
      }

      jbyteArray byte_arg = create_jbytearray(ctx.env, chunks[1], chunk_size[1]);

      if (!byte_arg) {
        fuzzing_print("ERROR: Failed to create jbyteArray argument\n");
        free_chunks(chunks, 2);
        return;
      }

      fuzzing_print("=== getChKey Arguments ===\n");
      fuzzing_print("arg1 (jlong): 0x%016llx (%lld)\n", (unsigned long long)long_arg, (long long)long_arg);
      print_jbytearray_content("arg2 (jbyteArray)", ctx.env, byte_arg);

      jstring result = getChKey_func(ctx.env, NULL, long_arg, byte_arg);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during getChKey call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("getChKey returned: %p\n", result);
        if (result) {
          print_jstring_content("Result", ctx.env, result);
          (*ctx.env)->DeleteLocalRef(ctx.env, result);
        }
      }

      (*ctx.env)->DeleteLocalRef(ctx.env, byte_arg);
      free_chunks(chunks, 2);
      break;
    }

    default: 
    case 5: {
      fuzzing_print("Fuzzing function getEncryptorKey (address 0x14744)\n");
      
      if (!getEncryptorKey_func) {
        fuzzing_print("ERROR: getEncryptorKey function not initialized\n");
        return;
      }

      uint32_t chunk_size[2] = {0};
      uint8_t **chunks = split_buffer(buffer + 1, length, 2, chunk_size);
      if (!chunks) {
        fuzzing_print("ERROR: Failed to split buffer for getEncryptorKey\n");
        return;
      }

      jstring str_arg1 = create_jstring(ctx.env, chunks[0], chunk_size[0]);
      jstring str_arg2 = create_jstring(ctx.env, chunks[1], chunk_size[1]);

      if (!str_arg1 || !str_arg2) {
        fuzzing_print("ERROR: Failed to create jstring arguments\n");
        if (str_arg1) (*ctx.env)->DeleteLocalRef(ctx.env, str_arg1);
        if (str_arg2) (*ctx.env)->DeleteLocalRef(ctx.env, str_arg2);
        free_chunks(chunks, 2);
        return;
      }

      fuzzing_print("=== getEncryptorKey Arguments ===\n");
      print_jstring_content("arg1 (jstring)", ctx.env, str_arg1);
      print_jstring_content("arg2 (jstring)", ctx.env, str_arg2);

      const char* result = getEncryptorKey_func(ctx.env, NULL, str_arg1, str_arg2);
      
      if ((*ctx.env)->ExceptionCheck(ctx.env)) {
        fuzzing_print("ERROR: JNI exception occurred during getEncryptorKey call\n");
        (*ctx.env)->ExceptionDescribe(ctx.env);
        (*ctx.env)->ExceptionClear(ctx.env);
      } else {
        fuzzing_print("getEncryptorKey returned: %p\n", result);
        if (result) {
          size_t result_len = strlen(result);
          print_hex_data("Result (const char*)", (const uint8_t*)result, result_len);
        }
      }

      (*ctx.env)->DeleteLocalRef(ctx.env, str_arg1);
      (*ctx.env)->DeleteLocalRef(ctx.env, str_arg2);
      free_chunks(chunks, 2);
      break;
    }
  
}

}


int main(int argc, char** argv) {
  int status;
  const uint8_t buffer[BUF_LEN];
  
  // Contains mocks for com.thingclips.smart.security.jni.JNICLibrary
  char* options[] = {
    "-Djava.class.path=/data/local/tmp/seclib/classes.dex" 
  };
  int num_options = sizeof(options) / sizeof(options[0]);

  fuzzing_print("[+] Initializing Java environment once at startup...\n");
  if ((status = init_java_env(&ctx, options, num_options)) != 0) {
    fuzzing_print("Failed to initialize Java environment: %d\n", status);
    return status;
  }
  fuzzing_print("[+] Java environment initialized successfully!\n");

  fuzzing_print("[+] Initializing function pointers...\n");
  if ((status = init_function_pointers()) != 0) {
    fuzzing_print("Failed to initialize function pointers: %d\n", status);
    cleanup_java_env(&ctx);
    return status;
  }
  fuzzing_print("[+] Function pointers initialized successfully!\n");

  #ifdef FUZZ_MODE
    ssize_t rlength = fread((void*)buffer, 1, BUF_LEN, stdin);
  #else
    if (argc < 2) {
      fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
      cleanup_java_env(&ctx);
      if (lib_handle) dlclose(lib_handle);
      return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (!file) {
      fuzzing_print("Failed to open input file\n");
      cleanup_java_env(&ctx);
      if (lib_handle) dlclose(lib_handle);
      return 1;
    }

    ssize_t rlength = fread((void*)buffer, 1, BUF_LEN, file);
    fclose(file);    
  #endif
  
  if (rlength == -1) {
    fuzzing_print("Error reading input file: %s\n", strerror(errno));
    cleanup_java_env(&ctx);
    if (lib_handle) dlclose(lib_handle);
    return errno;
  }

  // Call the fuzz function (this will be the persistent entry point for AFL)
  fuzz_main(buffer, rlength);

  cleanup_java_env(&ctx);
  if (lib_handle) {
    dlclose(lib_handle);
  }

  return 0;
}

