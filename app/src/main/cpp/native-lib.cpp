#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <climits>
#include <android/log.h>
#include <sys/ptrace.h>
#include <unistd.h>

/*
 * Defensive native layer for the JNI demo.
 *
 * This code is intentionally readable. The goal is a lab about signals and
 * architecture, not pretending that a few checks make an app invincible.
 */

#define LOG_TAG "ANTI_DEBUG"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

struct SecurityReport {
    bool tracerPidDetected = false;
    bool ptraceSuspicious = false;
    bool suspiciousMaps = false;
    std::string suspiciousMapLine;
    std::string details;
};

static SecurityReport lastReport;

static void appendLine(std::string &target, const std::string &line) {
    target += line;
    target += "\n";
}

// --------------------------------------------------
// Check 1A: safer tracing signal through /proc/self/status.
// --------------------------------------------------
static bool hasNonZeroTracerPid(std::string &details) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) {
        LOGW("Impossible d'ouvrir /proc/self/status");
        appendLine(details, "TracerPid: inconnu (/proc/self/status inaccessible)");
        return false;
    }

    char line[256];
    bool detected = false;

    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = 0;
            sscanf(line, "TracerPid:\t%d", &tracerPid);

            if (tracerPid > 0) {
                LOGE("Etat suspect : TracerPid=%d", tracerPid);
                appendLine(details, "TracerPid: suspect (" + std::to_string(tracerPid) + ")");
                detected = true;
            } else {
                LOGI("TracerPid=0");
                appendLine(details, "TracerPid: OK (0)");
            }
            break;
        }
    }

    fclose(status);
    return detected;
}

// --------------------------------------------------
// Check 1B: ptrace demonstration.
// --------------------------------------------------
static bool ptraceSelfCheck(std::string &details) {
    /*
     * PTRACE_TRACEME is a classic demo check:
     * if another tracer is already attached, it usually fails.
     *
     * Caveat:
     * This can be environment-dependent and has side effects, so real products
     * should combine multiple signals and test carefully.
     */
    errno = 0;
    long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);

    if (result == -1) {
        LOGE("Etat suspect : ptrace(PTRACE_TRACEME) a echoue, errno=%d", errno);
        appendLine(details, "ptrace: suspect (PTRACE_TRACEME failed, errno=" + std::to_string(errno) + ")");
        return true;
    }

    LOGI("Aucun trace/debug detecte via ptrace(PTRACE_TRACEME)");
    appendLine(details, "ptrace: OK (PTRACE_TRACEME accepted)");
    return false;
}

// --------------------------------------------------
// Check 2: scan /proc/self/maps for simple instrumentation signatures.
// --------------------------------------------------
static bool containsSuspiciousLibraryNames(std::string &details, std::string &matchedLine) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGW("Impossible d'ouvrir /proc/self/maps");
        appendLine(details, "maps: inconnu (/proc/self/maps inaccessible)");
        return false;
    }

    const char *signatures[] = {
            "frida",
            "xposed",
            "libfrida",
            "gdbserver",
            "libgdb",
            "magisk"
    };

    char line[512];

    while (fgets(line, sizeof(line), maps)) {
        for (const char *signature : signatures) {
            if (strstr(line, signature)) {
                matchedLine = line;
                LOGE("Signature suspecte trouvee dans maps : %s", line);
                appendLine(details, std::string("maps: suspect (signature ") + signature + ")");
                fclose(maps);
                return true;
            }
        }
    }

    fclose(maps);
    LOGI("Aucune signature suspecte trouvee dans /proc/self/maps");
    appendLine(details, "maps: OK (aucune signature simple)");
    return false;
}

static SecurityReport runSecurityChecks() {
    SecurityReport report;

    appendLine(report.details, "Controle natif JNI defensif");

    report.tracerPidDetected = hasNonZeroTracerPid(report.details);
    report.ptraceSuspicious = ptraceSelfCheck(report.details);
    report.suspiciousMaps = containsSuspiciousLibraryNames(
            report.details,
            report.suspiciousMapLine
    );

    if (report.tracerPidDetected || report.ptraceSuspicious || report.suspiciousMaps) {
        LOGE("Etat de securite : DEBUG / INSTRUMENTATION detecte");
        appendLine(report.details, "Decision: SUSPECT");
    } else {
        LOGI("Etat de securite : OK");
        appendLine(report.details, "Decision: OK");
    }

    return report;
}

// --------------------------------------------------
// JNI defensive API.
// --------------------------------------------------
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_jnidemo_MainActivity_isDebugDetected(
        JNIEnv * /* env */,
        jobject /* this */) {

    lastReport = runSecurityChecks();

    return (lastReport.tracerPidDetected
            || lastReport.ptraceSuspicious
            || lastReport.suspiciousMaps)
           ? JNI_TRUE
           : JNI_FALSE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_getSecurityDetails(
        JNIEnv *env,
        jobject /* this */) {

    if (lastReport.details.empty()) {
        lastReport = runSecurityChecks();
    }

    return env->NewStringUTF(lastReport.details.c_str());
}

// --------------------------------------------------
// Previous JNI lab functions.
// --------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_helloFromJNI(
        JNIEnv *env,
        jobject /* this */) {

    LOGI("helloFromJNI autorise");
    return env->NewStringUTF("Hello from C++ via JNI !");
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_MainActivity_factorial(
        JNIEnv * /* env */,
        jobject /* this */,
        jint n) {

    if (n < 0) {
        LOGE("Factoriel refuse : n negatif");
        return -1;
    }

    long long fact = 1;
    for (int i = 1; i <= n; i++) {
        fact *= i;
        if (fact > INT_MAX) {
            LOGE("Overflow detecte pour n=%d", n);
            return -2;
        }
    }

    LOGI("Factoriel de %d calcule en natif = %lld", n, fact);
    return static_cast<jint>(fact);
}
