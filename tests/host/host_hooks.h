#pragma once
#include <vector>
#include <string>

void host_reset_environment();
int host_lock_violations();
bool host_restarted();
std::vector<std::string> &host_events();
