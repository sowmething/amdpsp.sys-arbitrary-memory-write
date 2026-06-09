# amdpsp.sys arbitrary memory write vulnerability (0-day)

This repository contains a Proof of Concept (PoC) demonstrating a memory overwrite vulnerability via an exposed ioctl handler in the `AmdPsp` driver.

## ⚠️ Disclaimer
This code is provided exclusively for educational purposes, security research, and vulnerability mitigation verification. It is intended to demonstrate how unvalidated user-supplied pointers inside `DeviceIoControl` can lead to localized data corruption within user-space memory. The author (DevAddPhysicalMemory assumes no responsibility for misuse or damages resulting from this code.

## Vulnerability Overview

The vulnerability lies in how the driver handles the `0x9c422820` IOCTL code. When this IOCTL is invoked, the driver processes an input buffer containing user-defined offsets and virtual addresses, and attempts to write output data back to the location specified by the `lpOutBuffer` parameter in `DeviceIoControl`.

### How this PoC works

When the PoC runs, these things will happen:
Open the driver,
Allocate a memory and write Important data! Do not delete.
Exploit: Call the ioctl,
Check if data changed,
If changed, then its successful.

## How i found this vulnerability:
First i randomly found this driver and reversed the driver by ghidra and took a look at the ioctl codes. when i look at the vulnerable ioctl, 0x9c422820, i found this code:
```c
case 0x9c422820:
    if ((local_res20 == (undefined4 *)0x0) || (param_3 != 0x158)) goto LAB_140001c1c;
    if ((local_38[0] == (uint *)0x0) || (param_4 != 0x168)) goto LAB_140001ccf;
    uVar7 = FUN_140004d40((longlong *)*plVar5,(longlong)local_38[0],local_res20);
    uVar7 = uVar7 & 0xffffffff;
    break;
```

not suspicious right? but the actual vulnerability is at the function FUN_140004d40:

```c
ulonglong FUN_140004d40(longlong *param_1,longlong param_2,undefined4 *param_3)

{
  bool bVar1;
  undefined4 *puVar2;
  ulonglong uVar3;
  uint uVar4;
  undefined4 *local_res8;
  undefined8 local_res20;
  longlong local_428 [4];
  undefined4 local_404;
  undefined4 local_400;
  undefined4 local_3fc;
  undefined4 local_3f8;
  undefined4 local_3f4;
 
  local_res8 = (undefined4 *)0x0;
  if ((((param_1 == (longlong *)0x0) || (*param_1 == 0)) || (param_1[9] == 0)) || (param_1[10] == 0)
     ) {
    return 0xc000000d;
  }
  FUN_140006340(local_428,0,(undefined1 *)0x400);
  local_400 = *(undefined4 *)(param_2 + 0x158);
  local_3f8 = *(undefined4 *)(param_2 + 0x160);
  local_3fc = *(undefined4 *)(param_2 + 0x164);
  local_428[0] = 6;
  local_404 = 1;
  local_3f4 = local_400;
  uVar3 = FUN_140006170((longlong)param_1,local_428,&local_res8);
  puVar2 = local_res8;
  if ((int)uVar3 == 0) {
    bVar1 = false;
    uVar4 = 0;
    local_res20 = 0xffffffffffffd8f0;
    if (local_res8 != (undefined4 *)0x0) {
      do {
        if (puVar2[1] == 2) {
          bVar1 = true;
          break;
        }
        KeDelayExecutionThread(0,0,&local_res20);
        uVar4 = uVar4 + 1;
      } while (uVar4 < 0x1389);
      if (bVar1) {
        *param_3 = *puVar2;
        param_3[1] = puVar2[1];
        param_3[2] = puVar2[2];
        *(undefined4 *)((longlong)param_1 + (ulonglong)*(uint *)(param_2 + 0x15c) * 0x30 + 0x9c) =
             puVar2[8];
        param_3[4] = puVar2[8];
        return uVar3 & 0xffffffff;
      }
    }
    *param_3 = *puVar2; // vulnerability
    param_3[1] = puVar2[1]; //vulnerability
    param_3[2] = 0xffffffff; // vulnerability
    param_3[4] = 0; //vulnerability
    // because driver writes its data to the address we provided.
  }
  return uVar3 & 0xffffffff;
}
```

So thats it.
