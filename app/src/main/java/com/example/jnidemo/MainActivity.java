package com.example.jnidemo;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/**
 * Java side of the defensive JNI lab.
 *
 * MainActivity does not implement the anti-debug logic itself.
 * It asks the native library for a security signal, then decides what the UI
 * should do with that result.
 */
public class MainActivity extends Activity {

    /*
     * Defensive native entry point.
     *
     * It returns true if the native layer sees a suspicious execution context.
     */
    public native boolean isDebugDetected();

    /*
     * Extra lab helper:
     * returns a readable explanation of the native checks.
     * This makes the TP easier to validate without relying only on Logcat.
     */
    public native String getSecurityDetails();

    /*
     * Normal JNI functions from the previous lab.
     * The UI will call them only if the defensive check says the context is OK.
     */
    public native String helloFromJNI();

    public native int factorial(int n);

    static {
        /*
         * Must match add_library(native-lib ...) in CMakeLists.txt.
         * Android loads libnative-lib.so from the APK.
         */
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tvStatus = findViewById(R.id.tvStatus);
        TextView tvDetails = findViewById(R.id.tvDetails);
        TextView tvHello = findViewById(R.id.tvHello);
        TextView tvFact = findViewById(R.id.tvFact);

        /*
         * One JNI transition gives Java a simple policy signal.
         * This keeps the Java/native boundary clear and small.
         */
        boolean suspicious = isDebugDetected();
        String details = getSecurityDetails();

        tvDetails.setText(section("Details des controles natifs", details));

        if (suspicious) {
            /*
             * Pedagogical reaction:
             * do not crash; show a status and block sensitive native calls.
             */
            tvStatus.setText("Etat securite : environnement suspect detecte");
            tvStatus.setTextColor(getColor(R.color.alert_red));

            tvHello.setText(section("helloFromJNI", "Fonction native sensible desactivee"));
            tvFact.setText(section("factorial(10)", "Calcul natif bloque"));
        } else {
            tvStatus.setText("Etat securite : OK");
            tvStatus.setTextColor(getColor(R.color.ok_green));

            tvHello.setText(section("helloFromJNI", helloFromJNI()));

            int result = factorial(10);
            tvFact.setText(section(
                    "factorial(10)",
                    result >= 0
                            ? "Factoriel de 10 = " + result
                            : "Erreur factoriel, code = " + result
            ));
        }
    }

    private String section(String title, String body) {
        return title + "\n" + body;
    }
}
