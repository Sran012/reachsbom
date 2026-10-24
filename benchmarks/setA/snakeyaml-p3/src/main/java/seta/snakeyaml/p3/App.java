package seta.snakeyaml.p3;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
