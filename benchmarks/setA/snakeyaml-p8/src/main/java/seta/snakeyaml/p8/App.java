package seta.snakeyaml.p8;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        System.out.println("snakeyaml-p8: vulnerable call is never reached");
    }

    private static void unused() {
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
