function dynamicJavascript(code: string): unknown {
  // ruleid: decky.javascript.dynamic-execution
  return eval(code);
}

function dynamicFunction(code: string): Function {
  // ruleid: decky.javascript.dynamic-execution
  return new Function(code);
}

function ordinaryValue(value: string): string {
  // ok: decky.javascript.dynamic-execution
  return value.toUpperCase();
}
