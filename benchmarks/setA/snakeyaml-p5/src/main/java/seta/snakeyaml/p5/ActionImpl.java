package seta.snakeyaml.p5;

public final class ActionImpl implements Action {
    @Override
    public void run() {
        Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");
    }
}
