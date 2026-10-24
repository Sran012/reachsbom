package seta.log4j.p4;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        step1();
    }

    private static void step1() throws Exception {
        step2();
    }

    private static void step2() throws Exception {
        step3();
    }

    private static void step3() throws Exception {
        org.apache.logging.log4j.core.net.JndiManager.getDefaultManager().lookup("ldap://127.0.0.1:1389/x");
    }
}
