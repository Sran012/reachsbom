package seta.commons.p9;

final class P9Call {
    private P9Call() {
    }

    static void run() {
        new org.apache.commons.text.StringSubstitutor().replace("${x}");
    }
}
