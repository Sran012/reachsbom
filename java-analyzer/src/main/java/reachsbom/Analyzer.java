package reachsbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import soot.Body;
import soot.G;
import soot.Kind;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.DefinitionStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.NewExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public final class Analyzer {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> JDK_PREFIXES = Set.of(
            "java.", "javax.", "jdk.", "sun.", "com.sun."
    );

    public static void main(String[] args) throws Exception {
        String requestPath = null;
        String outputPath = null;
        for (int i = 0; i < args.length; i++) {
            if ("--request".equals(args[i]) && i + 1 < args.length) {
                requestPath = args[++i];
            } else if ("--output".equals(args[i]) && i + 1 < args.length) {
                outputPath = args[++i];
            }
        }
        if (requestPath == null || outputPath == null) {
            System.err.println("usage: java -jar reachsbom-analyzer.jar --request request.json --output response.json");
            System.exit(2);
        }

        JsonNode request = JSON.readTree(new File(requestPath));
        String algorithm = request.path("algorithm").asText("rta");
        boolean useEdgeRules = request.path("use_edge_rules").asBoolean(true);

        List<AppSpec> apps = new ArrayList<>();
        for (JsonNode node : request.path("apps")) {
            apps.add(AppSpec.fromJson(node));
        }
        if (apps.isEmpty()) {
            throw new IllegalArgumentException("request has no apps");
        }

        long started = System.currentTimeMillis();
        ObjectNode response = run(apps, algorithm, useEdgeRules, started);
        JSON.writerWithDefaultPrettyPrinter().writeValue(new File(outputPath), response);
    }

    private static ObjectNode run(List<AppSpec> apps, String algorithm, boolean useEdgeRules, long started) throws IOException {
        List<String> appDirs = new ArrayList<>();
        Set<String> appDirSet = new LinkedHashSet<>();
        Set<String> runtimeJarSet = new LinkedHashSet<>();
        for (AppSpec app : apps) {
            appDirs.addAll(app.appDirs);
            appDirSet.addAll(app.appDirs);
            runtimeJarSet.addAll(app.runtimeJars);
        }

        Set<String> symbolClasses = new LinkedHashSet<>();
        for (AppSpec app : apps) {
            for (SymbolSpec symbol : app.symbols) {
                symbolClasses.add(symbol.className);
            }
        }

        G.reset();
        Options.v().set_whole_program(true);
        Options.v().set_app(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_verbose(false);
        Options.v().set_debug(false);
        Options.v().set_soot_classpath(joinPaths(appDirs, runtimeJarSet));
        Options.v().set_process_dir(new ArrayList<>(appDirSet));
        Options.v().set_main_class(apps.get(0).mainClass);

        for (String name : symbolClasses) {
            try {
                Scene.v().addBasicClass(name, SootClass.SIGNATURES);
            } catch (RuntimeException ignored) {
                // The class is not on this classpath. The Python side reports it as absent.
            }
        }
        for (AppSpec app : apps) {
            Scene.v().addBasicClass(app.mainClass, SootClass.BODIES);
        }

        Scene.v().loadNecessaryClasses();

        List<SootMethod> entries = new ArrayList<>();
        for (AppSpec app : apps) {
            app.appClassNames = collectClassNames(app.appDirs);
            SootClass mainClass = Scene.v().getSootClassUnsafe(app.mainClass, false);
            if (mainClass == null) {
                throw new IllegalStateException("main class not loaded: " + app.mainClass);
            }
            SootMethod main = mainClass.getMethodByName("main");
            app.entry = main;
            app.roots.add(main);
            entries.add(main);
            for (String className : app.appClassNames) {
                SootClass candidate = Scene.v().getSootClassUnsafe(className, false);
                if (candidate == null) {
                    continue;
                }
                for (SootMethod method : candidate.getMethods()) {
                    if (isHttpHandler(method) || isFrameworkEntry(method)) {
                        app.roots.add(method);
                        entries.add(method);
                    }
                }
            }
        }
        Scene.v().setEntryPoints(entries);
        soot.PackManager.v().getPack("cg").apply();
        CallGraph callGraph = Scene.v().getCallGraph();

        ObjectNode root = JSON.createObjectNode();
        ObjectNode appsNode = root.putObject("apps");

        for (AppSpec app : apps) {
            long appStarted = System.currentTimeMillis();
            BfsResult cha = bfsCha(app.entry, callGraph, Collections.emptyMap());
            Set<SootClass> instantiated = instantiatedClasses(cha.seen);

            Map<SootMethod, List<ExtraEdge>> extras = new HashMap<>();
            if (app.reflection) {
                addReflectionExtras(app, extras);
            }
            if (useEdgeRules) {
                for (JsonNode rule : app.edgeRules) {
                    String type = rule.path("type").asText("");
                    if ("method_map".equals(type)) {
                        addMethodMapRule(app, rule, extras, "cha".equalsIgnoreCase(algorithm));
                    } else if ("service_loader".equals(type)) {
                        addServiceLoaderRule(app, rule, extras);
                    }
                }
            }

            for (SootMethod entryRoot : app.roots) {
                if (!entryRoot.equals(app.entry)) {
                    extras.computeIfAbsent(app.entry, k -> new ArrayList<>())
                            .add(new ExtraEdge(entryRoot, "ENTRY"));
                }
            }

            BfsResult reachable;
            if ("cha".equalsIgnoreCase(algorithm)) {
                reachable = bfsCha(app.entry, callGraph, extras);
            } else {
                reachable = bfsRta(app.entry, callGraph, instantiated, extras);
            }

            app.dynamic = false;
            for (SootMethod method : app.dynamicMethods) {
                if (reachable.seen.contains(method)) {
                    app.dynamic = true;
                    break;
                }
            }

            ObjectNode appNode = appsNode.putObject(app.id);
            ObjectNode symbolsNode = appNode.putObject("symbols");
            String strongest = "Present";
            for (SymbolSpec symbol : app.symbols) {
                for (String signature : symbol.methods) {
                    ObjectNode result = analyzeSymbol(symbol, signature, reachable, app);
                    symbolsNode.set(signature, result);
                    String status = result.path("status").asText("Present");
                    strongest = strongest(strongest, status);
                }
            }
            appNode.put("status", strongest);
            appNode.put("dynamic", app.dynamic);

            ObjectNode stats = appNode.putObject("stats");
            stats.put("graph_edges", callGraph.size());
            stats.put("reachable_methods", reachable.seen.size());
            stats.put("instantiated_classes", instantiated.size());
            stats.put("time_ms", System.currentTimeMillis() - appStarted);
        }

        root.put("time_ms", System.currentTimeMillis() - started);
        return root;
    }

    private static ObjectNode analyzeSymbol(SymbolSpec symbol, String signature, BfsResult reachable, AppSpec app) {
        ObjectNode result = JSON.createObjectNode();
        SootClass targetClass = Scene.v().getSootClassUnsafe(symbol.className, false);
        boolean classPresent = targetClass != null && !targetClass.isPhantom();
        SootMethod target = null;
        if (classPresent) {
            try {
                target = Scene.v().getMethod(signature);
            } catch (RuntimeException ignored) {
                target = null;
            }
        }
        boolean methodPresent = target != null;
        boolean isReachable = methodPresent && reachable.seen.contains(target);
        String status;
        if (!classPresent) {
            status = "Present";
        } else if (isReachable) {
            status = "Reachable";
        } else if (app.dynamic) {
            status = "PossiblyReachable";
        } else {
            status = "ClassPresent";
        }

        result.put("class_present", classPresent);
        result.put("method_present", methodPresent);
        result.put("status", status);
        ArrayNode path = result.putArray("path");
        if (isReachable) {
            for (String item : buildPath(target, reachable)) {
                path.add(item);
            }
        }
        return result;
    }

    private static List<String> buildPath(SootMethod target, BfsResult result) {
        List<String> path = new ArrayList<>();
        SootMethod current = target;
        Set<SootMethod> guard = new HashSet<>();
        while (current != null && guard.add(current)) {
            path.add(current.getSignature());
            if (current.equals(result.entry)) {
                break;
            }
            current = result.parent.get(current);
        }
        Collections.reverse(path);
        if (path.size() > 14) {
            List<String> trimmed = new ArrayList<>();
            trimmed.addAll(path.subList(0, 4));
            trimmed.add("...");
            trimmed.addAll(path.subList(path.size() - 8, path.size()));
            return trimmed;
        }
        return path;
    }

    private static String strongest(String left, String right) {
        return rank(right) > rank(left) ? right : left;
    }

    private static int rank(String status) {
        switch (status) {
            case "Reachable": return 4;
            case "PossiblyReachable": return 3;
            case "ClassPresent": return 2;
            case "Present": return 1;
            default: return 0;
        }
    }

    private static BfsResult bfsCha(SootMethod entry, CallGraph graph,
                                    Map<SootMethod, List<ExtraEdge>> extras) {
        BfsResult result = new BfsResult(entry);
        ArrayDeque<SootMethod> queue = new ArrayDeque<>();
        result.seen.add(entry);
        queue.add(entry);
        while (!queue.isEmpty()) {
            SootMethod current = queue.poll();
            for (ExtraEdge extra : extras.getOrDefault(current, Collections.emptyList())) {
                if (extra.target != null && result.seen.add(extra.target)) {
                    result.parent.put(extra.target, current);
                    result.via.put(extra.target, extra.kind);
                    queue.add(extra.target);
                }
            }
            if (isJdk(current.getDeclaringClass().getName())) {
                continue;
            }
            for (Iterator<Edge> it = graph.edgesOutOf(current); it.hasNext(); ) {
                Edge edge = it.next();
                if (edge.kind() == Kind.GENERIC_FAKE) {
                    continue;
                }
                SootMethod next = edge.tgt();
                if (next == null || result.seen.contains(next)) {
                    continue;
                }
                result.seen.add(next);
                result.parent.put(next, current);
                result.via.put(next, edge.kind().toString());
                queue.add(next);
            }
        }
        return result;
    }

    private static BfsResult bfsRta(SootMethod entry, CallGraph graph, Set<SootClass> instantiated,
                                    Map<SootMethod, List<ExtraEdge>> extras) {
        BfsResult result = new BfsResult(entry);
        ArrayDeque<SootMethod> queue = new ArrayDeque<>();
        result.seen.add(entry);
        queue.add(entry);
        while (!queue.isEmpty()) {
            SootMethod current = queue.poll();

            for (ExtraEdge extra : extras.getOrDefault(current, Collections.emptyList())) {
                if (extra.target != null && result.seen.add(extra.target)) {
                    result.parent.put(extra.target, current);
                    result.via.put(extra.target, extra.kind);
                    instantiated.addAll(instantiatedClasses(Set.of(extra.target)));
                    queue.add(extra.target);
                }
            }

            if (isJdk(current.getDeclaringClass().getName())) {
                continue;
            }

            for (Iterator<Edge> it = graph.edgesOutOf(current); it.hasNext(); ) {
                Edge edge = it.next();
                if (edge.kind() == Kind.GENERIC_FAKE) {
                    continue;
                }
                SootMethod next = edge.tgt();
                if (next == null || result.seen.contains(next)) {
                    continue;
                }
                SootClass targetClass = next.getDeclaringClass();
                if (edge.isInstance() && !instantiated.contains(targetClass)
                        && !targetClass.isInterface() && !targetClass.isAbstract()) {
                    continue;
                }
                result.seen.add(next);
                result.parent.put(next, current);
                result.via.put(next, edge.kind().toString());
                queue.add(next);
            }
        }
        return result;
    }

    private static Set<SootClass> instantiatedClasses(Set<SootMethod> methods) {
        Set<SootClass> result = new HashSet<>();
        for (SootMethod method : methods) {
            if (!method.isConcrete() || isJdk(method.getDeclaringClass().getName())) {
                continue;
            }
            try {
                Body body = method.retrieveActiveBody();
                for (Unit unit : body.getUnits()) {
                    if (unit instanceof DefinitionStmt) {
                        Value right = ((DefinitionStmt) unit).getRightOp();
                        if (right instanceof NewExpr) {
                            result.add(((NewExpr) right).getBaseType().getSootClass());
                        }
                    }
                }
            } catch (RuntimeException ignored) {
                // A phantom or native body does not instantiate anything.
            }
        }
        return result;
    }

    private static void addMethodMapRule(AppSpec app, JsonNode rule, Map<SootMethod, List<ExtraEdge>> extras,
                                         boolean chaMode) {
        List<SootMethod> sources = new ArrayList<>();
        List<SootMethod> targets = new ArrayList<>();
        Set<String> sourceSignatures = new HashSet<>();
        String sourceOwner = rule.path("source_owner").asText("");
        String sourceFirstParam = rule.path("source_first_param").asText("");
        Set<String> sourceNames = new HashSet<>();
        for (JsonNode node : rule.path("source_names")) {
            sourceNames.add(node.asText());
        }
        for (JsonNode node : rule.path("sources")) {
            for (SootMethod method : findMatchingMethods(node.asText())) {
                sources.add(method);
                sourceSignatures.add(method.getSignature());
            }
        }
        for (JsonNode node : rule.path("targets")) {
            SootMethod method = findMethod(node.asText());
            if (method != null) {
                targets.add(method);
            }
        }

        boolean appOnly = "app".equals(rule.path("scope").asText("all")) && !chaMode;
        if (appOnly) {
            for (String className : app.appClassNames) {
                SootClass sootClass = Scene.v().getSootClassUnsafe(className, false);
                if (sootClass == null) {
                    continue;
                }
                for (SootMethod method : sootClass.getMethods()) {
                    if (!method.isConcrete()) {
                        continue;
                    }
                    Body body;
                    try {
                        body = method.retrieveActiveBody();
                    } catch (RuntimeException ignored) {
                        continue;
                    }
                    boolean callsSource = false;
                    for (Unit unit : body.getUnits()) {
                        if (!(unit instanceof Stmt) || !((Stmt) unit).containsInvokeExpr()) {
                            continue;
                        }
                        SootMethod invoked = ((Stmt) unit).getInvokeExpr().getMethod();
                        if (matchesSource(invoked, sourceSignatures, sourceOwner, sourceNames, sourceFirstParam)) {
                            callsSource = true;
                            break;
                        }
                    }
                    if (callsSource) {
                        for (SootMethod target : targets) {
                            extras.computeIfAbsent(method, k -> new ArrayList<>())
                                    .add(new ExtraEdge(target, "RULE"));
                        }
                    }
                }
            }
            return;
        }

        if (!sourceOwner.isEmpty()) {
            for (SootClass sootClass : Scene.v().getClasses()) {
                for (SootMethod method : sootClass.getMethods()) {
                    if (matchesSource(method, sourceSignatures, sourceOwner, sourceNames, sourceFirstParam)) {
                        sources.add(method);
                    }
                }
            }
        }

        for (SootMethod source : sources) {
            for (SootMethod target : targets) {
                extras.computeIfAbsent(source, k -> new ArrayList<>())
                        .add(new ExtraEdge(target, "RULE"));
            }
        }
    }

    private static boolean matchesSource(SootMethod method, Set<String> exactSignatures,
                                         String owner, Set<String> names, String firstParam) {
        if (exactSignatures.contains(method.getSignature())) {
            return true;
        }
        if (owner.isEmpty() || names.isEmpty()) {
            return false;
        }
        if (!method.getDeclaringClass().getName().equals(owner)) {
            return false;
        }
        if (!names.contains(method.getName()) || method.getParameterCount() == 0) {
            return false;
        }
        if (!firstParam.isEmpty() && !method.getParameterType(0).toString().equals(firstParam)) {
            return false;
        }
        return true;
    }

    private static boolean isFrameworkEntry(SootMethod method) {
        if (!"run".equals(method.getName()) || method.getParameterCount() != 1) {
            return false;
        }
        return implementsType(method.getDeclaringClass(), "org.springframework.boot.ApplicationRunner")
                || implementsType(method.getDeclaringClass(), "org.springframework.boot.CommandLineRunner");
    }

    private static boolean implementsType(SootClass start, String target) {
        ArrayDeque<SootClass> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        queue.add(start);
        while (!queue.isEmpty()) {
            SootClass current = queue.poll();
            if (current == null || !seen.add(current.getName())) {
                continue;
            }
            if (current.getName().equals(target)) {
                return true;
            }
            for (SootClass iface : current.getInterfaces()) {
                queue.add(iface);
            }
            if (current.hasSuperclass()) {
                queue.add(current.getSuperclass());
            }
        }
        return false;
    }

    private static boolean isHttpHandler(SootMethod method) {
        for (soot.tagkit.Tag tag : method.getTags()) {
            if (tag instanceof soot.tagkit.VisibilityAnnotationTag) {
                for (soot.tagkit.AnnotationTag annotation
                        : ((soot.tagkit.VisibilityAnnotationTag) tag).getAnnotations()) {
                    String type = annotation.getType();
                    if (type.contains("GetMapping") || type.contains("PostMapping")
                            || type.contains("PutMapping") || type.contains("DeleteMapping")
                            || type.contains("PatchMapping") || type.contains("RequestMapping")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static void addServiceLoaderRule(AppSpec app, JsonNode rule, Map<SootMethod, List<ExtraEdge>> extras) {
        String interfaceName = rule.path("interface").asText("");
        String methodName = rule.path("method").asText("run");
        if (interfaceName.isEmpty()) {
            return;
        }
        SootClass serviceLoader = loadClass("java.util.ServiceLoader");
        if (serviceLoader == null) {
            return;
        }
        List<SootMethod> sources = new ArrayList<>();
        for (SootMethod method : serviceLoader.getMethods()) {
            if ("load".equals(method.getName()) || "iterator".equals(method.getName())) {
                sources.add(method);
            }
        }

        for (String dir : app.appDirs) {
            Path serviceFile = Paths.get(dir, "META-INF", "services", interfaceName);
            if (!Files.isRegularFile(serviceFile)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(serviceFile, StandardCharsets.UTF_8)) {
                    String provider = line.trim();
                    if (provider.isEmpty() || provider.startsWith("#")) {
                        continue;
                    }
                    SootClass providerClass = loadClass(provider);
                    if (providerClass == null) {
                        continue;
                    }
                    for (SootMethod method : providerClass.getMethods()) {
                        if (method.getName().equals(methodName) && method.getParameterCount() == 0) {

                            for (SootMethod source : sources) {
                                extras.computeIfAbsent(source, k -> new ArrayList<>())
                                        .add(new ExtraEdge(method, "RULE"));
                            }
                        }
                    }
                }
            } catch (IOException ignored) {
                // A broken service file just means no framework edge.
            }
        }
    }

    private static void addReflectionExtras(AppSpec app, Map<SootMethod, List<ExtraEdge>> extras) {
        for (String className : app.appClassNames) {
            SootClass sootClass = Scene.v().getSootClassUnsafe(className, false);
            if (sootClass == null) {
                continue;
            }
            for (SootMethod method : sootClass.getMethods()) {
                if (!method.isConcrete()) {
                    continue;
                }
                Body body;
                try {
                    body = method.retrieveActiveBody();
                } catch (RuntimeException ignored) {
                    continue;
                }
                String forName = null;
                boolean dynamic = false;
                List<String> methodNames = new ArrayList<>();
                List<Integer> methodArity = new ArrayList<>();
                for (Unit unit : body.getUnits()) {
                    if (!(unit instanceof Stmt) || !((Stmt) unit).containsInvokeExpr()) {
                        continue;
                    }
                    InvokeExpr invoke = ((Stmt) unit).getInvokeExpr();
                    SootMethod callee = invoke.getMethod();
                    String owner = callee.getDeclaringClass().getName();
                    if (!"java.lang.Class".equals(owner)) {
                        continue;
                    }
                    if ("forName".equals(callee.getName()) && invoke.getArgCount() > 0) {
                        Value value = invoke.getArg(0);
                        if (value instanceof StringConstant) {
                            forName = ((StringConstant) value).value;
                        } else {
                            dynamic = true;
                        }
                    }
                    if (("getMethod".equals(callee.getName()) || "getDeclaredMethod".equals(callee.getName()))
                            && invoke.getArgCount() > 0) {
                        Value value = invoke.getArg(0);
                        if (value instanceof StringConstant) {
                            methodNames.add(((StringConstant) value).value);
                            methodArity.add(invoke.getArgCount() - 1);
                        } else {
                            dynamic = true;
                        }
                    }
                }
                if (dynamic) {
                    app.dynamicMethods.add(method);
                }
                if (forName == null || methodNames.isEmpty()) {
                    continue;
                }
                SootClass targetClass = loadClass(forName);
                if (targetClass == null) {
                    continue;
                }
                for (int i = 0; i < methodNames.size(); i++) {
                    String name = methodNames.get(i);
                    int arity = methodArity.get(i);
                    boolean found = false;
                    for (SootMethod target : targetClass.getMethods()) {
                        if (target.getName().equals(name) && target.getParameterCount() == arity) {
                            extras.computeIfAbsent(method, k -> new ArrayList<>())
                                    .add(new ExtraEdge(target, "REFLECTION"));
                            found = true;
                        }
                    }
                    if (!found) {
                        for (SootMethod target : targetClass.getMethods()) {
                            if (target.getName().equals(name)) {
                                extras.computeIfAbsent(method, k -> new ArrayList<>())
                                        .add(new ExtraEdge(target, "REFLECTION"));
                            }
                        }
                    }
                }
            }
        }
    }

    private static List<SootMethod> findMatchingMethods(String signature) {
        int colon = signature.indexOf(':');
        int close = signature.lastIndexOf('>');
        if (colon < 0 || close <= colon) {
            SootMethod single = findMethod(signature);
            return single == null ? Collections.emptyList() : List.of(single);
        }
        String subSignature = signature.substring(colon + 1, close).trim();
        List<SootMethod> result = new ArrayList<>();
        for (SootClass sootClass : Scene.v().getClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.getSubSignature().equals(subSignature)) {
                    result.add(method);
                }
            }
        }
        if (result.isEmpty()) {
            SootMethod single = findMethod(signature);
            if (single != null) {
                result.add(single);
            }
        }
        return result;
    }

    private static SootMethod findMethod(String signature) {
        try {
            return Scene.v().getMethod(signature);
        } catch (RuntimeException ignored) {
            int colon = signature.indexOf(':');
            if (colon > 1) {
                String className = signature.substring(1, colon);
                loadClass(className);
                try {
                    return Scene.v().getMethod(signature);
                } catch (RuntimeException ignoredAgain) {
                    return null;
                }
            }
            return null;
        }
    }

    private static SootClass loadClass(String name) {
        SootClass existing = Scene.v().getSootClassUnsafe(name, false);
        if (existing != null && !existing.isPhantom()) {
            return existing;
        }
        try {
            return Scene.v().loadClassAndSupport(name);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static boolean isJdk(String className) {
        for (String prefix : JDK_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> collectClassNames(List<String> dirs) throws IOException {
        Set<String> names = new HashSet<>();
        for (String dir : dirs) {
            Path root = Paths.get(dir);
            if (!Files.isDirectory(root)) {
                continue;
            }
            try (var stream = Files.walk(root)) {
                for (Path path : stream.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList())) {
                    String relative = root.relativize(path).toString().replace(File.separatorChar, '.');
                    String name = relative.substring(0, relative.length() - ".class".length());
                    if (!name.equals("module-info") && !name.endsWith("module-info")) {
                        names.add(name);
                    }
                }
            }
        }
        return names;
    }

    private static String joinPaths(List<String> dirs, Set<String> jars) {
        List<String> all = new ArrayList<>(dirs);
        all.addAll(jars);
        return String.join(File.pathSeparator, all);
    }

    private static final class BfsResult {
        final SootMethod entry;
        final Set<SootMethod> seen = new HashSet<>();
        final Map<SootMethod, SootMethod> parent = new HashMap<>();
        final Map<SootMethod, String> via = new HashMap<>();

        BfsResult(SootMethod entry) {
            this.entry = entry;
        }
    }

    private static final class ExtraEdge {
        final SootMethod target;
        final String kind;

        ExtraEdge(SootMethod target, String kind) {
            this.target = target;
            this.kind = kind;
        }
    }

    private static final class SymbolSpec {
        final String key;
        final String className;
        final List<String> methods;

        SymbolSpec(String key, String className, List<String> methods) {
            this.key = key;
            this.className = className;
            this.methods = methods;
        }

        static SymbolSpec fromJson(JsonNode node) {
            List<String> methods = new ArrayList<>();
            for (JsonNode method : node.path("methods")) {
                methods.add(method.asText());
            }
            return new SymbolSpec(node.path("key").asText(""), node.path("class").asText(""), methods);
        }
    }

    private static final class AppSpec {
        final String id;
        final String mainClass;
        final List<String> appDirs;
        final List<String> runtimeJars;
        final List<SymbolSpec> symbols;
        final JsonNode edgeRules;
        final boolean reflection;
        final Set<SootMethod> dynamicMethods = new HashSet<>();
        final List<SootMethod> roots = new ArrayList<>();
        SootMethod entry;
        Set<String> appClassNames = new HashSet<>();
        boolean dynamic;

        AppSpec(String id, String mainClass, List<String> appDirs, List<String> runtimeJars,
                List<SymbolSpec> symbols, JsonNode edgeRules, boolean reflection) {
            this.id = id;
            this.mainClass = mainClass;
            this.appDirs = appDirs;
            this.runtimeJars = runtimeJars;
            this.symbols = symbols;
            this.edgeRules = edgeRules;
            this.reflection = reflection;
        }

        static AppSpec fromJson(JsonNode node) {
            List<String> appDirs = new ArrayList<>();
            for (JsonNode item : node.path("app_dirs")) {
                appDirs.add(item.asText());
            }
            List<String> jars = new ArrayList<>();
            for (JsonNode item : node.path("runtime_jars")) {
                jars.add(item.asText());
            }
            List<SymbolSpec> symbols = new ArrayList<>();
            for (JsonNode item : node.path("symbols")) {
                symbols.add(SymbolSpec.fromJson(item));
            }
            return new AppSpec(
                    node.path("id").asText(),
                    node.path("main_class").asText(),
                    appDirs,
                    jars,
                    symbols,
                    node.path("edge_rules"),
                    node.path("reflection").asBoolean(true)
            );
        }
    }
}
