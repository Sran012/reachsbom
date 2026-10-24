package seta.snakeyaml.p6;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("org.yaml.snakeyaml.Yaml");
        Object instance = clazz.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method method = clazz.getMethod("load", String.class);
        method.invoke(instance, "a: 1");
    }
}
