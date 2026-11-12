/* Generate KernelSU's allowlist file (/data/adb/ksu/.allowlist).
 *
 * The kernel loads this file at module init (ksu_load_allow_list) and from it
 * builds the per-uid authorisation table. Without a valid file the module
 * denies every uid except the Manager, so this is the only way to grant an app
 * root on this port (the Manager UI's Superuser tab is unavailable here).
 *
 * Format:  u32 magic | u32 version | N * struct app_profile
 *          magic   = 0x7f4b5355  ('KSU')
 *          version = 4           (KSU_APP_PROFILE_VER at v3.3.0)
 *
 * Build:
 *   cc -I<kernelsu>/uapi gen-allowlist.c -o gen-allowlist
 *     (needs uapi/app_profile.h from the KernelSU tree, so the struct layout
 *      always matches the module you are pairing it with)
 *
 * Usage:
 *   ./gen-allowlist out.bin 2000,10087
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_profile.h"

/* If this fires, upstream changed the struct: re-check profile_valid() in
 * kernel/policy/allowlist.c and regenerate, do not just bump the number. */
_Static_assert(sizeof(struct app_profile) == 784,
               "app_profile layout changed; re-verify against allowlist.c");

#define ALLOWLIST_MAGIC 0x7f4b5355u
#define ALLOWLIST_VER 4u

static void put_profile(FILE *f, int uid) {
  struct app_profile p;
  memset(&p, 0, sizeof(p));
  p.version = ALLOWLIST_VER;
  snprintf(p.key, sizeof(p.key), "uid%d", uid);
  p.curr_uid = uid;
  p.allow_su = true;

  /* use_default keeps the built-in root profile (uid/gid 0, full caps).
   * selinux_domain must be non-empty or profile_valid() rejects the entry. */
  p.rp_config.use_default = true;
  p.rp_config.profile.uid = 0;
  p.rp_config.profile.gid = 0;
  p.rp_config.profile.groups_count = 1;
  p.rp_config.profile.groups[0] = 0;
  p.rp_config.profile.namespaces = 0;
  strncpy(p.rp_config.profile.selinux_domain, "u:r:su:s0",
          sizeof(p.rp_config.profile.selinux_domain) - 1);

  fwrite(&p, sizeof(p), 1, f);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("usage: %s <out.bin> <uid[,uid...]>\n", argv[0]);
    printf("sizeof(struct app_profile) = %zu\n", sizeof(struct app_profile));
    return 1;
  }

  FILE *f = fopen(argv[1], "wb");
  if (!f) {
    perror("open");
    return 1;
  }

  uint32_t magic = ALLOWLIST_MAGIC, ver = ALLOWLIST_VER;
  fwrite(&magic, 4, 1, f);
  fwrite(&ver, 4, 1, f);

  char *list = strdup(argv[2]);
  int n = 0;
  for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
    put_profile(f, atoi(tok));
    n++;
  }
  fclose(f);
  printf("wrote %d profile(s), %d bytes\n", n,
         8 + n * (int)sizeof(struct app_profile));
  return 0;
}
