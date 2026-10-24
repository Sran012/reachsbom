package seta.snakeyaml.p9;

final class P9Call {
    private P9Call() {
    }

    static void run() {
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
