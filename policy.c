/**
 * Process the policy.
 * Copyright (C) 2016 Peter Wu <peter@lekensteyn.nl>

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include "dnsallow.h"

struct policy {
};

struct policy *policy_init(void)
{
    struct policy *policy;

    policy = malloc(sizeof(*policy));
    if (!policy)
        return NULL;

    /* TODO read policy from given file. */

    return policy;
}

/**
 * Returns zero if the policy accepts the name and non-zero otherwise.
 */
int policy_check(struct policy *policy, const char *dnsname)
{
    /* TODO apply policy */
    return 0;
}

void policy_fini(struct policy *policy)
{
    free(policy);
}
