package seta.log4j.p6;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("org.apache.logging.log4j.core.lookup.JndiLookup");
        Object instance = clazz.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method method = clazz.getMethod("lookup", org.apache.logging.log4j.core.LogEvent.class, String.class);
        method.invoke(instance, null, "x");
    }
}
