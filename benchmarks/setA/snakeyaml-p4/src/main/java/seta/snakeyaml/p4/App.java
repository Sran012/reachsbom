package seta.snakeyaml.p4;

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
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
