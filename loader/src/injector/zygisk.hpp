#pragma once

#include <stdint.h>
#include <jni.h>
#include <vector>

extern void *self_handle;
extern void *loader_handle;

void hook_functions();

void revert_unmount_ksu();

void revert_unmount_magisk();

