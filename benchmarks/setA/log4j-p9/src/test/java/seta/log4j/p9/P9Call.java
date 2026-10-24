package seta.log4j.p9;

final class P9Call {
    private P9Call() {
    }

    static void run() throws Exception {
        org.apache.logging.log4j.core.net.JndiManager.getDefaultManager().lookup("ldap://127.0.0.1:1389/x");
    }
}
