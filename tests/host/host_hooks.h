#pragma once
#include <vector>
#include <string>

void host_reset_environment();
int host_lock_violations();
bool host_restarted();
std::vector<std::string> &host_events();
void host_set_fido_source(int s);
void host_break_fido_source(int s, bool broken);
