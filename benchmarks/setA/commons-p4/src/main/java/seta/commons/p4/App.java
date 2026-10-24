package seta.commons.p4;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        step1();
    }

    private static void step1() {
        step2();
    }

    private static void step2() {
        step3();
    }

    private static void step3() {
        new org.apache.commons.text.StringSubstitutor().replace("${x}");
    }
}
