package seta.log4j.p5;

public final class App {
    private App() {
    }

    public static void main(String[] args) throws Exception {
        Action action = new ActionImpl();
        action.run();
    }
}
