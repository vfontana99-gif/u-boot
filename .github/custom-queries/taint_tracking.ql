import cpp
import semmle.code.cpp.dataflow.TaintTracking

// Classe Sorgente (Sorgente di rete)
class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("^ntoh.*") and
      this = mi.getExpr()
    )
  }
}

// Utilizzo di un modulo per configurare il Taint Tracking
module NetworkToMemcpyConfig implements DataFlow::ConfigSig {
  
  // Definizione della Sorgente
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  // Definizione del Sink
  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" and
      sink.asExpr() = call.getArgument(2) // Parametro "size" (indice 2)
    )
  }
}

// Creazione del flusso globale collegando la configurazione utilizzata
module NetworkToMemcpyFlow = TaintTracking::Global<NetworkToMemcpyConfig>;

// Esecuzione della ricerca
from DataFlow::Node source, DataFlow::Node sink
where NetworkToMemcpyFlow::flow(source, sink)
select sink, "Vulnerabilità RCE (CVE) trovata! Dati non validati in memcpy.", source, "Vai alla Sorgente"
