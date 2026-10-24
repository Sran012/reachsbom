package seta.snakeyaml.p5;

public final class App {
    private App() {
    }

    public static void main(String[] args) {
        Action action = new ActionImpl();
        action.run();
    }
}
