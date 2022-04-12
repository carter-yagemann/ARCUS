# Checking for Intel Processor Trace (PT) Support

If you do not know whether your CPU supports Intel PT,
you can compile and run the following C program:

```c
/*
 * Copyright 2019 Carter Yagemann <yagemann@gatech.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* Quick and dirty check for Intel Processor Trace (PT) features. */
#include <cpuid.h>
#include <stdio.h>

unsigned check_bit(unsigned reg, int bit) {
    return (reg >> bit) & 1;
}

void main() {
    unsigned eax, ebx, ecx, edx;
    if (__get_cpuid(0x00, &eax, &ebx, &ecx, &edx) == 0) {
        printf("CPUID not supported\n");
        return;
    }

    if (eax < 0x14) {
        printf("Intel PT not supported\n");
        return;
    }

    __cpuid_count(0x7, 0x00, eax, ebx, ecx, edx);
    if (!(check_bit(ebx, 25))) {
        printf("Intel PT           : no\n");
        return;
    }
    printf("Intel PT           : YES\n");

    printf("\n");
    __cpuid_count(0x14, 0x00, eax, ebx, ecx, edx);
    if (check_bit(ebx, 0))
        printf("CR3 Filtering      : YES\n");
    else
        printf("CR3 Filtering      : no\n");

    if (check_bit(ebx, 2))
        printf("IP Filtering       : YES\n");
    else
        printf("IP Filtering       : no\n");

    if (check_bit(ebx, 1))
        printf("PSB/CYC Accurate   : YES\n");
    else
        printf("PSB/CYC Accurate   : no\n");

    if (check_bit(ebx, 3))
        printf("MTC Packets        : YES\n");
    else
        printf("MTC Packets        : no\n");

    if (check_bit(ebx, 4))
        printf("PTWRITE            : YES\n");
    else
        printf("PTWRITE            : no\n");

    if (check_bit(ebx, 5))
        printf("Power Events       : YES\n");
    else
        printf("Power Events       : no\n");

    if (check_bit(ecx, 2))
        printf("Single-Range Output: YES\n");
    else
        printf("Single-Range Output: no\n");

    if (check_bit(ecx, 0))
        printf("ToPA Output        : YES\n");
    else
        printf("ToPA Output        : no\n");

    if (check_bit(ecx, 1))
        printf("ToPA Multi-Output  : YES\n");
    else
        printf("ToPA Multi-Output  : no\n");

    if (check_bit(ecx, 3))
        printf("TT Subsys Output   : YES\n");
    else
        printf("TT Subsys Output   : no\n");
    printf("\n");

    if (check_bit(ecx, 31))
        printf("IP Playloads       : LIP\n");
    else
        printf("IP Payloads        : RIP\n");

    if (eax < 1)
        return;

    __cpuid_count(0x14, 0x01, eax, ebx, ecx, edx);
    printf("Address Ranges     : %d\n", eax & 0x7);
}
```

ARCUS requires `Intel PT` and `ToPA Output` to work.
