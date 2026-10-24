package seta.commons.p6;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("org.apache.commons.text.StringSubstitutor");
        Object instance = clazz.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method method = clazz.getMethod("replace", String.class);
        method.invoke(instance, "${x}");
    }
}
