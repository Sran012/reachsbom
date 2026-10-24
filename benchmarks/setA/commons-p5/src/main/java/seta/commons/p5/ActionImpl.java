package seta.commons.p5;

public final class ActionImpl implements Action {
    @Override
    public void run() {
        new org.apache.commons.text.StringSubstitutor().replace("${x}");
    }
}
