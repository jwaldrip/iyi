// The type id's three homes, measured: GC_DESIGN.md, "The last eight bytes".
//   cc -O2 -o /tmp/d bench/dispatch_probe.c && taskset -c 2 /tmp/d
// n is the working set: a million objects is out of cache, a hundred thousand in.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
// Three ways to find an object's type id, on the same 1M objects of 24-byte
// chunks in 16 MB arenas, visited in a shuffled order (a list's order, not a
// sweep's): (a) the header word at P-8; (b) one id per arena, at the arena's
// head; (c) one byte per chunk in a side table at the arena's head, the
// chunk's index by a multiply-and-shift reciprocal of the chunk size.
#define MAP (16u<<20)
#define HEAD 4096
static uint64_t now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000000000ull+t.tv_nsec;}
int main(int argc,char**argv){
  size_t n=argc>1?strtoul(argv[1],0,10):1000000, chunk=24, per=(MAP-HEAD-(MAP/chunk))/chunk; // side table room
  size_t arenas=(n+per-1)/per;
  uint8_t**objs=malloc(n*sizeof(*objs));
  uint8_t**bases=malloc(arenas*sizeof(*bases));
  for(size_t a=0;a<arenas;a++){
    void*raw=mmap(0,MAP*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    uint8_t*base=(uint8_t*)(((uintptr_t)raw+MAP-1)&~(uintptr_t)(MAP-1));
    bases[a]=base;
    *(uint32_t*)(base+16)=7; *(uint64_t*)(base+24)=((1ull<<40)+chunk-1)/chunk;
    memset(base+HEAD, 3, MAP/chunk);            // (c) side table, a byte a chunk
  }
  size_t table=MAP/chunk, first=HEAD+table; first=(first+7)&~7ul;
  for(size_t i=0;i<n;i++){ size_t a=i/per, k=i%per; uint8_t*obj=bases[a]+first+k*chunk+8; objs[i]=obj; *(uint32_t*)(obj-4)=5; }
  // shuffle
  srand(1); for(size_t i=n-1;i>0;i--){size_t j=rand()%(i+1);uint8_t*t=objs[i];objs[i]=objs[j];objs[j]=t;}
  uint64_t magic=((1ull<<40)+chunk-1)/chunk; // floor(x/24) via (x*magic)>>40 for x < 2^24
  for(int rep=0;rep<3;rep++){
    uint64_t s=0,t0=now();
    for(size_t i=0;i<n;i++) s+=*(uint32_t*)(objs[i]-4)+*(uint32_t*)(objs[i]);
    uint64_t t1=now();
    for(size_t i=0;i<n;i++){ uintptr_t o=(uintptr_t)objs[i]; s+=*(uint32_t*)((o&~(uintptr_t)(MAP-1))+16)+*(uint32_t*)o; }
    uint64_t t2=now();
    for(size_t i=0;i<n;i++){ uintptr_t o=(uintptr_t)objs[i]; uintptr_t b=o&~(uintptr_t)(MAP-1); uint64_t idx=((o-b-first)*magic)>>40; s+=*(uint8_t*)(b+HEAD+idx)+*(uint32_t*)o; }
    uint64_t t3=now();
    // (d) side table, but the chunk size read from the arena head (the real case: 67 classes)
    for(size_t i=0;i<n;i++){ uintptr_t o=(uintptr_t)objs[i]; uintptr_t b=o&~(uintptr_t)(MAP-1); uint64_t m=*(uint64_t*)(b+24); uint64_t idx=((o-b-first)*m)>>40; s+=*(uint8_t*)(b+HEAD+idx)+*(uint32_t*)o; }
    uint64_t t4=now();
    printf("with a field read too: header P-4 %.2f ns  arena-head %.2f ns  side-table(const magic) %.2f ns  side-table(magic from arena) %.2f ns  (sink %llu)\n",(t1-t0)/(double)n,(t2-t1)/(double)n,(t3-t2)/(double)n,(t4-t3)/(double)n,(unsigned long long)s);
  }
  return 0;
}
