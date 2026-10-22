# Analyzer API

The Python orchestrator writes one request JSON file and calls the Java analyzer.

    java -Xmx3g -jar java-analyzer/target/reachsbom-analyzer.jar \
      --request request.json --output response.json

## Request

    {
      "algorithm": "rta",
      "use_edge_rules": true,
      "apps": [
        {
          "id": "log4j-p3",
          "main_class": "seta.log4j.p3.App",
          "app_dirs": ["/abs/path/target/classes"],
          "runtime_jars": ["/abs/path/target/runtime-jars/x.jar"],
          "symbols": [
            {
              "key": "CVE-2021-44228",
              "class": "org.apache.logging.log4j.core.net.JndiManager",
              "methods": ["<org.apache.logging.log4j.core.net.JndiManager: java.lang.Object lookup(java.lang.String)>"]
            }
          ],
          "edge_rules": [
            {
              "type": "method_map",
              "sources": ["<org.apache.logging.log4j.Logger: void error(java.lang.String)>"],
              "targets": ["<org.apache.logging.log4j.core.lookup.JndiLookup: java.lang.String lookup(org.apache.logging.log4j.core.LogEvent,java.lang.String)>"],
              "reason": "Log4j plugin lookup dispatch"
            }
          ],
          "reflection": true
        }
      ]
    }

All apps in one request share one Soot Scene. App class directories are
different. Runtime jars are the union for the batch.

## Response

    {
      "apps": {
        "log4j-p3": {
          "symbols": {
            "<method signature>": {
              "class_present": true,
              "method_present": true,
              "status": "Reachable",
              "path": ["<entry>", "<callee>", "<target>"],
              "dynamic": false
            }
          },
          "dynamic": false,
          "stats": {
            "graph_edges": 123,
            "reachable_methods": 45,
            "instantiated_classes": 12,
            "time_ms": 900
          }
        }
      }
    }

Status is one of Present, ClassPresent, PossiblyReachable, Reachable.
The Python side turns these into the labels used by the report.

The analyzer never expands calls inside the JDK. Calls from app or library
code into the JDK are recorded, but the JDK body is not followed. Framework
callbacks are added by edge rules.
