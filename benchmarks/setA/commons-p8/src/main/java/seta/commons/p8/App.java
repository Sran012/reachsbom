package seta.commons.p8;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        System.out.println("commons-p8: vulnerable call is never reached");
    }

    private static void unused() {
        new org.apache.commons.text.StringSubstitutor().replace("${x}");
    }
}
