package seta.log4j.p7;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName(args[0]);
        Object instance = clazz.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method method = clazz.getMethod("lookup", org.apache.logging.log4j.core.LogEvent.class, String.class);
        method.invoke(instance, null, "x");
    }
}
