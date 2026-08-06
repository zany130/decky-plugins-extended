function reviewChildProcess(): void {
  // ruleid: decky.javascript.child-process-exec
  require("node:child_process").exec("echo review-fixture");
}
