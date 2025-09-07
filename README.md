# NTAPI Wrapper Library

Eine kleine C-Library, die wichtige **Native API (NTAPI)** Funktionen aus `ntdll.dll` dynamisch auflöst.  
Damit lassen sich NT-Funktionen bequem wie normale Windows-APIs nutzen, ohne jedes Mal `GetProcAddress` schreiben zu müssen.

1. **`ntinclude.h` und `ntinclude.c`** in der `main.c` einbinden.
   Unter Visual Studio reicht es, beide Dateien zum Projekt hinzuzufügen
   oder auf der Kommandozeile zu kompilieren:

   ```
   cl /EHsc main.c ntinclude.c
   ```

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

NTSTATUS status = NtAllocateVirtualMemory(
    GetCurrentProcess(),
    &addr,
    0,
    &size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

if (NT_SUCCESS(status)) {
    printf("Speicher allokiert bei %p\n", addr);
} else {
    printf("NtAllocateVirtualMemory fehlgeschlagen: 0x%lx\n", status);
}
```

  
