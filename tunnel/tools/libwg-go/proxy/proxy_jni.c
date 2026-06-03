#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>
#include <unistd.h>
#include <pthread.h>

static pthread_mutex_t g_protector_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_status_mutex = PTHREAD_MUTEX_INITIALIZER;

#define LOG_TAG "AmneziaWG/BypassSocket"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

struct go_string { const char *str; long n; };

extern int awgStartProxy(struct go_string ifname, struct go_string settings, struct go_string uapipath, int bypass);
extern void awgStopProxy();
extern char *awgGetProxyConfig(int handle);
extern int awgUpdateProxyTunnelPeers(int handle, struct go_string settings);
extern void awgTurnProxyTunnelOff(int handle);

// Global JNI state
static JavaVM *g_jvm = NULL;

// Socket protector
static jobject g_protector = NULL;
static jmethodID g_protectMethod = NULL;

// Status callback
static jobject g_statusCallbackObj = NULL;
static jmethodID g_statusCallbackMethod = NULL;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    LOGD("JNI_OnLoad: g_jvm cached = %p", g_jvm);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) == JNI_OK) {
        if (g_protector != NULL) {
            (*env)->DeleteGlobalRef(env, g_protector);
            g_protector = NULL;
        }
        if (g_statusCallbackObj != NULL) {
            (*env)->DeleteGlobalRef(env, g_statusCallbackObj);
            g_statusCallbackObj = NULL;
        }
    }
    g_protectMethod = NULL;
    g_statusCallbackMethod = NULL;
    g_jvm = NULL;
    LOGD("JNI_OnUnload: cleared all globals");
}

JNIEXPORT jint JNICALL Java_com_zaneschepke_tunnel_ProxyBackend_awgStartProxy(JNIEnv *env, jclass c, jstring ifname, jstring settings, jstring uapipath, jint bypass)
{
    const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
    size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
    const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
    size_t settings_len = (*env)->GetStringUTFLength(env, settings);
    const char *uapipath_str = (*env)->GetStringUTFChars(env, uapipath, 0);
        size_t uapipath_len = (*env)->GetStringUTFLength(env, uapipath);
    int ret = awgStartProxy((struct go_string){
        .str = ifname_str,
        .n = ifname_len
    }, (struct go_string){
        .str = settings_str,
        .n = settings_len
    }, (struct go_string){
            .str = uapipath_str,
            .n = uapipath_len
        },bypass);
    (*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
    (*env)->ReleaseStringUTFChars(env, settings, settings_str);
    (*env)->ReleaseStringUTFChars(env, uapipath, uapipath_str);
    return ret;
}

JNIEXPORT void JNICALL Java_com_zaneschepke_tunnel_ProxyBackend_awgTurnProxyTunnelOff(JNIEnv *env, jclass c, jint handle)
{
    awgTurnProxyTunnelOff(handle);
}

JNIEXPORT jstring JNICALL Java_com_zaneschepke_tunnel_ProxyBackend_awgGetProxyConfig(JNIEnv *env, jclass c, jint handle)
{
    jstring ret;
    char *config = awgGetProxyConfig(handle);
    if (!config)
        return NULL;
    ret = (*env)->NewStringUTF(env, config);
    free(config);
    return ret;
}

JNIEXPORT void JNICALL Java_com_zaneschepke_tunnel_ProxyBackend_awgSetSocketProtector(
        JNIEnv *env, jclass c, jobject protector) {
    pthread_mutex_lock(&g_protector_mutex);
    LOGD("JNI: awgSetSocketProtector called from Kotlin - protector=%p", protector);

    // Clear old protector
    if (g_protector != NULL) {
        (*env)->DeleteGlobalRef(env, g_protector);
        g_protector = NULL;
        g_protectMethod = NULL;
        LOGD("JNI: Cleared previous socket protector");
    }

    if (protector != NULL) {
        g_protector = (*env)->NewGlobalRef(env, protector);
        LOGD("JNI: Created new global ref for protector = %p", g_protector);

        jclass protectorClass = (*env)->GetObjectClass(env, protector);
        if (protectorClass != NULL) {
            g_protectMethod = (*env)->GetMethodID(env, protectorClass, "bypass", "(I)I");
            (*env)->DeleteLocalRef(env, protectorClass);
        }

        if (g_protectMethod != NULL) {
            LOGD("JNI: Socket protector SUCCESSFULLY REGISTERED (methodID = %p)", g_protectMethod);
        } else {
            LOGE("JNI: FAILED to get bypass method ID");
        }
    } else {
        LOGD("JNI: Socket protector CLEARED (null passed)");
    }
    pthread_mutex_unlock(&g_protector_mutex);
}

int bypass_socket(int fd) {
    if (fd < 0) {
        LOGE("Invalid FD passed to bypass_socket: %d", fd);
        return 0;  // Fail early on bad FD
    }

    JNIEnv *env = NULL;
    jboolean attached = JNI_FALSE;
    jint rs = -1;

    LOGD("bypass_socket called with FD: %d", fd);

    if (g_jvm == NULL) {
        LOGE("g_jvm is NULL");
        return 0;
    }

    rs = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rs == JNI_EDETACHED) {
        int retries = 3;
        while (retries-- > 0 && (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            usleep(10000); // 10ms backoff
        }
        if (retries < 0) {
            LOGE("AttachCurrentThread failed after retries");
            return 0;
        }
        attached = JNI_TRUE;
    } else if (rs != JNI_OK) {
        LOGE("GetEnv failed with %d", rs);
        return 0;
    }

    if (env == NULL) {
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return 0;
    }

    pthread_mutex_lock(&g_protector_mutex);
    if (g_protector == NULL || g_protectMethod == NULL) {
        pthread_mutex_unlock(&g_protector_mutex);
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return 0;
    }

    jobject local_protector = (*env)->NewLocalRef(env, g_protector);
    jmethodID local_method = g_protectMethod;
    pthread_mutex_unlock(&g_protector_mutex);

    if (local_protector == NULL) {
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return 0;
    }

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    int result = (*env)->CallIntMethod(env, local_protector, local_method, fd);

    if ((*env)->ExceptionCheck(env)) {
        LOGE("Exception thrown from CallIntMethod");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        result = 0;
    }

    (*env)->DeleteLocalRef(env, local_protector);

    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }

    return result;
}

JNIEXPORT jint JNICALL Java_com_zaneschepke_tunnel_ProxyBackend_awgUpdateProxyTunnelPeers(JNIEnv *env, jclass c, jint handle, jstring settings)
{
    const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
    size_t settings_len = (*env)->GetStringUTFLength(env, settings);
    int ret = awgUpdateProxyTunnelPeers(handle, (struct go_string){
        .str = settings_str,
        .n = settings_len
    });
    (*env)->ReleaseStringUTFChars(env, settings, settings_str);
    return ret;
}

JNIEXPORT void JNICALL Java_com_zaneschepke_tunnel_VpnBackend_awgSetStatusCallback(
        JNIEnv *env, jclass clazz, jobject callback) {
    pthread_mutex_lock(&g_status_mutex);
    LOGD("JNI: awgSetStatusCallback called - callback=%p", callback);

    if (g_statusCallbackObj != NULL) {
        (*env)->DeleteGlobalRef(env, g_statusCallbackObj);
        g_statusCallbackObj = NULL;
        g_statusCallbackMethod = NULL;
    }

    if (callback != NULL) {
        g_statusCallbackObj = (*env)->NewGlobalRef(env, callback);
        jclass callbackClass = (*env)->GetObjectClass(env, callback);
        if (callbackClass != NULL) {
            g_statusCallbackMethod = (*env)->GetMethodID(env, callbackClass,
                    "onStatusChanged", "(II)V");
            (*env)->DeleteLocalRef(env, callbackClass);
        }
        if (g_statusCallbackMethod != NULL) {
            LOGD("JNI: Status callback SUCCESSFULLY REGISTERED (2-param)");
        } else {
            LOGE("JNI: FAILED to get onStatusChanged method ID");
        }
    } else {
        LOGD("JNI: Status callback CLEARED");
    }
    pthread_mutex_unlock(&g_status_mutex);
}


void awgNotifyStatus(int32_t handle, int32_t code) {
    JNIEnv *env = NULL;
    jboolean attached = JNI_FALSE;
    jint rs = -1;

    if (g_jvm == NULL) {
        LOGE("JNI: awgNotifyStatus called but g_jvm is NULL");
        return;
    }

    rs = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);
    if (rs == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            LOGE("JNI: AttachCurrentThread failed in awgNotifyStatus");
            return;
        }
        attached = JNI_TRUE;
    } else if (rs != JNI_OK) {
        LOGE("JNI: GetEnv failed with %d in awgNotifyStatus", rs);
        return;
    }

    if (env == NULL) {
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return;
    }

    pthread_mutex_lock(&g_status_mutex);
    if (g_statusCallbackObj == NULL || g_statusCallbackMethod == NULL) {
        pthread_mutex_unlock(&g_status_mutex);
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return;
    }

    jobject local_callback = (*env)->NewLocalRef(env, g_statusCallbackObj);
    jmethodID local_method = g_statusCallbackMethod;
    pthread_mutex_unlock(&g_status_mutex);

    if (local_callback == NULL) {
        if (attached) (*g_jvm)->DetachCurrentThread(g_jvm);
        return;
    }

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    (*env)->CallVoidMethod(env, local_callback, local_method, (jint)handle, (jint)code);

    if ((*env)->ExceptionCheck(env)) {
        LOGE("Exception thrown from awgNotifyStatus CallVoidMethod");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, local_callback);

    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}