#include <dlfcn.h>
#include <stdbool.h>
#include <signal.h>
#include "jenv.h"

#define LOG_TAG "jenv"
#define ANDROID_RUNTIME_DSO "libandroid_runtime.so"
#define ART_DSO "libart.so"

typedef jint(*JNI_CreateJavaVM_t)(JavaVM **p_vm, JNIEnv **p_env, void *vm_args);


int init_java_env(JavaCTX *ctx, char **jvm_options, uint8_t jvm_nb_options) {
  JNI_CreateJavaVM_t JNI_CreateJVM;
  JniInvocationImpl* (*JniInvocation_ctor)(JniInvocationImpl*);  // Constructor
  bool (*JniInvocation_Init)(JniInvocationImpl*, const char*);   // Init method
  jint (*registerFrameworkNatives)(JNIEnv*);
  void* runtime_dso;
  const char* runtime_lib = ANDROID_RUNTIME_DSO;

  ALOGV("[+] Initialize Java environment");

  // Try Android runtime first, then ART if that fails
  if ((runtime_dso = dlopen(runtime_lib, RTLD_NOW)) == NULL) {
    ALOGW("[!] Failed to load %s: %s, trying ART instead", runtime_lib, dlerror());
    runtime_lib = ART_DSO;
    if ((runtime_dso = dlopen(runtime_lib, RTLD_NOW)) == NULL) {
      ALOGE("[!] Failed to load %s: %s", runtime_lib, dlerror());
      return JNI_ERR;
    }
  }
  
  ALOGD("[+] Successfully loaded %s", runtime_lib);

  // Look for the mangled C++ symbols
  JniInvocation_ctor = dlsym(runtime_dso, "_ZN13JniInvocationC1Ev");
  if (JniInvocation_ctor == NULL) {
    ALOGW("[!] JniInvocation constructor not found: %s\n", dlerror());
  }

  JniInvocation_Init = dlsym(runtime_dso, "_ZN13JniInvocation4InitEPKc");
  if (JniInvocation_Init == NULL) {
    ALOGW("[!] JniInvocation::Init not found: %s\n", dlerror());
  }

  if ((JNI_CreateJVM = (JNI_CreateJavaVM_t) dlsym(runtime_dso, "JNI_CreateJavaVM")) == NULL) {
    ALOGE("[!] Failed to find JNI_CreateJavaVM: %s", dlerror());
    return JNI_ERR;
  }
  
  ALOGD("[+] Found JNI_CreateJavaVM function");

  registerFrameworkNatives = dlsym(runtime_dso, "registerFrameworkNatives");
  if (registerFrameworkNatives == NULL) {
    ALOGW("[!] registerFrameworkNatives not found: %s\n", dlerror());
  }

  ALOGV("[+] Required JNI functions found\n");

  // Initialize JniInvocation as recommended in the Stack Overflow answer
  if (JniInvocation_ctor && JniInvocation_Init) {
    // Allocate memory for the JniInvocation C++ object
    ctx->invoc = malloc(sizeof(void*) * 16); // Enough space for the C++ object
    if (ctx->invoc == NULL) {
      ALOGE("[!] Failed to allocate memory for JniInvocation");
      return JNI_ERR;
    }
    
    // Call the constructor
    JniInvocation_ctor(ctx->invoc);
    
    // Call the Init method with nullptr to use default runtime (as per SO answer)
    if (!JniInvocation_Init(ctx->invoc, NULL)) {
      ALOGW("[!] JniInvocation::Init failed, trying with explicit runtime library");
      if (!JniInvocation_Init(ctx->invoc, runtime_lib)) {
        ALOGE("[!] JniInvocation::Init failed with explicit library");
        free(ctx->invoc);
        ctx->invoc = NULL;
        // Continue without JniInvocation
      } else {
        ALOGD("[+] JniInvocation initialized with explicit runtime library");
      }
    } else {
      ALOGD("[+] JniInvocation initialized successfully");
    }
  } else {
    ALOGD("[d] JniInvocation functions not available, using direct JNI_CreateJavaVM");
    ctx->invoc = NULL;
  }

  JavaVMOption options[jvm_nb_options];

  for (int i = 0; i < jvm_nb_options; ++i)
    options[i].optionString = jvm_options[i];

  JavaVMInitArgs args;
  args.version = JNI_VERSION_1_6;
  args.nOptions = jvm_nb_options;
  args.options = options;
  args.ignoreUnrecognized = JNI_TRUE;

  ALOGV("[+] Java VM options set: %d options", jvm_nb_options);
  
  // Enhanced error handling for JNI_CreateJVM
  ALOGD("[+] About to call JNI_CreateJVM...");
  ALOGD("[+] VM args - version: 0x%x, nOptions: %d, ignoreUnrecognized: %s", 
        args.version, args.nOptions, args.ignoreUnrecognized ? "true" : "false");
  
  // Log all JVM options for debugging
  for (int i = 0; i < jvm_nb_options; i++) {
    ALOGD("[+] JVM Option %d: %s", i, options[i].optionString ? options[i].optionString : "(null)");
  }
  
  // Validate pointers before calling JNI_CreateJVM
  if (!JNI_CreateJVM) {
    ALOGE("[!] JNI_CreateJVM function pointer is NULL!");
    return JNI_ERR;
  }
  
  if (!ctx) {
    ALOGE("[!] JavaCTX context is NULL!");
    return JNI_ERR;
  }
  
  // Initialize pointers to NULL before the call
  ctx->vm = NULL;
  ctx->env = NULL;
  
  ALOGD("[+] Calling JNI_CreateJVM (function at %p)...", JNI_CreateJVM);
  
  // Set up signal handling for potential crashes during JVM creation
  struct sigaction old_action;
  struct sigaction new_action;
  new_action.sa_handler = SIG_DFL;  // Use default handler to get core dump
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;
  
  // Temporarily install default signal handlers to get better crash info
  sigaction(SIGABRT, &new_action, &old_action);
  
  jint status;
  
  // Use a try-catch like approach with setjmp/longjmp could be added here if needed
  // For now, just call the function with extensive logging
  
  status = JNI_CreateJVM(&ctx->vm, &ctx->env, &args);
  
  // Restore original signal handler
  sigaction(SIGABRT, &old_action, NULL);
  
  ALOGD("[+] JNI_CreateJVM returned with status: %d", status);
  ALOGD("[+] VM pointer: %p, ENV pointer: %p", ctx->vm, ctx->env);
  
  if (status != JNI_OK) {
    ALOGE("[!] Failed to create Java VM: %d", status);
    
    // Provide detailed error information based on status code
    switch (status) {
      case JNI_EDETACHED:
        ALOGE("[!] Error: Thread detached from the VM (JNI_EDETACHED)");
        break;
      case JNI_EVERSION:
        ALOGE("[!] Error: JNI version error (JNI_EVERSION)");
        break;
      case JNI_ENOMEM:
        ALOGE("[!] Error: Not enough memory (JNI_ENOMEM)");
        break;
      case JNI_EEXIST:
        ALOGE("[!] Error: VM already created (JNI_EEXIST)");
        break;
      case JNI_EINVAL:
        ALOGE("[!] Error: Invalid arguments (JNI_EINVAL)");
        break;
      default:
        ALOGE("[!] Error: Unknown JNI error code: %d", status);
        break;
    }
    
    // Additional debugging: try to get more info about the system state
    ALOGE("[!] System debugging info:");
    ALOGE("[!] - Runtime library used: %s", runtime_lib);
    ALOGE("[!] - JNI_CreateJVM function address: %p", JNI_CreateJVM);
    ALOGE("[!] - Context address: %p", ctx);
    ALOGE("[!] - Args address: %p", &args);
    
    return status;
  } 

  ALOGV("[d] vm: %p, env: %p\n", ctx->vm, ctx->env);

  // Only register framework natives if the function is available
  if (registerFrameworkNatives) {
    status = registerFrameworkNatives(ctx->env);
    if (status != JNI_OK){
      ALOGW("[!] Failed to register framework natives: %d (continuing anyway)", status);
      // Don't return error - framework natives may not be critical for basic JNI
    } else {
      ALOGD("[+] Framework natives registered successfully");
    }
  } else {
    ALOGD("[!] registerFrameworkNatives function not found, skipping registration (this is acceptable)");
  }

  return JNI_OK;
}

int cleanup_java_env(JavaCTX *ctx) {
  void (*JniInvocation_dtor)(JniInvocationImpl*);
  void* runtime_dso;

  ALOGV("[+] Cleanup Java environment");

  if (ctx == NULL || ctx->vm == NULL) return JNI_ERR;

  // Only cleanup JniInvocation if it was used
  if (ctx->invoc != NULL) {
    // Try to reopen the runtime library for cleanup
    if ((runtime_dso = dlopen(ANDROID_RUNTIME_DSO, RTLD_NOW)) == NULL) {
      // Try ART if Android runtime fails
      if ((runtime_dso = dlopen(ART_DSO, RTLD_NOW)) == NULL) {
        ALOGE("[!] Failed to reopen runtime library for cleanup: %s", dlerror());
        return JNI_ERR;
      }
    }

    if ((JniInvocation_dtor = dlsym(runtime_dso, "_ZN13JniInvocationD1Ev")) == NULL) {
      ALOGE("[!] JniInvocation destructor not found: %s\n", dlerror());
      return JNI_ERR;
    }

    JniInvocation_dtor(ctx->invoc);
    free(ctx->invoc);
    ctx->invoc = NULL;
  }

  (*ctx->vm)->DetachCurrentThread(ctx->vm);
  (*ctx->vm)->DestroyJavaVM(ctx->vm);

  return JNI_OK;
}
