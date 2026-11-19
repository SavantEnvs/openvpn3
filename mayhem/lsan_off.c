/* Leak detection off for every fuzz and standalone binary (leaks are not the bug class fuzzed here);
 * ASan and UBSan stay fully active. */
int __lsan_is_turned_off(void) { return 1; }
