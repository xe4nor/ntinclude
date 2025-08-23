# NTAPI Wrapper Library

Eine kleine C-Library, die wichtige **Native API (NTAPI)** Funktionen aus `ntdll.dll` dynamisch auflöst.  
Damit lassen sich NT-Funktionen bequem wie normale Windows-APIs nutzen, ohne jedes Mal `GetProcAddress` schreiben zu müssen.

1. **`ntapi.h` und `ntapi.c`** in der `main.c` einbinden:  

2. Beim Start **Resolver aufrufen**:  

   ```c
   if (!ResolveNtFunctions()) {
       printf("Fehler beim Laden der NT-Funktionen!\n");
       return 1;
   }
   ```

## Nutzung

### Beispiel: Speicher allokieren

```c
SIZE_T size = 0x1000;
PVOID addr = NULL;

if (NtAllocateVirtualMemory(
    GetCurrentProcess(),
    &addr,
    0,
    &size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
)) {
    printf("Speicher allokiert bei %p\n", addr);
}
```

  
