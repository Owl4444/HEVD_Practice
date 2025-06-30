#pragma once
#include <stdint.h>

/*
 dt ntkrnlmp!_POOL_HEADER
   +0x000 PreviousSize     : Pos 0, 8 Bits
   +0x000 PoolIndex        : Pos 8, 8 Bits
   +0x002 BlockSize        : Pos 0, 8 Bits
   +0x002 PoolType         : Pos 8, 8 Bits
   +0x000 Ulong1           : Uint4B
   +0x004 PoolTag          : Uint4B
   +0x008 ProcessBilled    : Ptr64 _EPROCESS
   +0x008 AllocatorBackTraceIndex : Uint2B
   +0x00a PoolTagHash      : Uint2B
*/




typedef struct _HEAP_VS_CHUNK_HEADER
{
    uint16_t MemoryCost;
    uint16_t UnsafeSize;
    uint16_t UnsafePrevSize;
    uint8_t Allocated;
    uint8_t Unused1;
    uint8_t EncodedSegmentPageOffset;
    uint8_t Unused2[7];
} HEAP_VS_CHUNK_HEADER;
static_assert(sizeof(HEAP_VS_CHUNK_HEADER) == 0x10, "HEAP_VS_CHUNK_HEADER must be 0x10 bytes");

// ref: https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_POOL_HEADER
typedef struct _POOL_HEADER
{
    uint8_t PreviousSize;
    uint8_t PoolIndex;
    uint8_t BlockSize;
    uint8_t PoolType;
    uint32_t PoolTag;
    uintptr_t ProcessBilled;
} POOL_HEADER;
static_assert(sizeof(POOL_HEADER) == 0x10, "POOL_HEADER must be 0x10 bytes");

// ref: https://github.com/reactos/reactos/blob/c2c66af/drivers/filesystems/npfs/npfs.h#L148
typedef struct _NP_DATA_QUEUE_ENTRY
{
    LIST_ENTRY QueueEntry;
    uintptr_t Irp;
    uintptr_t ClientSecurityContext;
    unsigned long DataEntryType;
    unsigned long QuotaInEntry;
    unsigned long DataSize;
    unsigned long unknown;
    char data[0];
} NP_DATA_QUEUE_ENTRY;
static_assert(sizeof(NP_DATA_QUEUE_ENTRY) == 0x30, "NP_DATA_QUEUE_ENTRY must be 0x30 bytes");


// Exploit structures
typedef struct vs_chunk
{
    uintptr_t encoded_vs_header[2];
    POOL_HEADER pool_header;
    NP_DATA_QUEUE_ENTRY np_data_queue_entry;
} xVS_DQE_HEADER_CHUNK;

typedef struct _IRP
{
    uint64_t Unused[3];
    uint64_t SystemBuffer;
} IRP;



//typedef struct _POOL_HEADER
//{
//    uint8_t PreviousSize;
//    uint8_t PoolIndex;
//    uint8_t BlockSize;
//    uint8_t PoolType;
//    uint32_t PoolTag;
//    uintptr_t ProcessBilled;
//}POOL_HEADER, * PPOOL_HEADER;
//
//
//typedef union _HEAP_VS_CHUNK_HEADER_SIZE
//{
//    uint32_t MemoryCost : 1;                                                     //0x0
//    uint32_t UnsafeSize : 15;                                                    //0x0
//    uint32_t UnsafePrevSize : 15;                                                //0x0
//    uint32_t Allocated : 1;                                                      //0x0
//    uint16_t KeyUShort;                                                       //0x0
//    uint32_t KeyULong;                                                         //0x0
//    uint32_t HeaderBits;                                                       //0x0
//}HEAP_VS_CHUNK_HEADER_SIZE, * PHEAP_VS_CHUNK_HEADER_SIZE;
//
//
//
//typedef struct _HEAP_VS_CHUNK_HEADER
//{
//    uint16_t MemoryCost;
//    uint16_t UnsafeSize;
//    uint16_t UnsafePrevSize;
//    uint8_t Allocated;
//    uint8_t Unused1;
//    uint8_t EncodedSegmentPageOffset;
//    uint8_t Unused2[7];
//} HEAP_VS_CHUNK_HEADER;
//
//typedef struct _NP_DATA_QUEUE_ENTRY
//{
//        LIST_ENTRY NextEntry;
//        PVOID Irp;
//        PVOID SecurityContext;
//        ULONG EntryType;
//        ULONG QuotaInEntry;
//        ULONG DataSize;
//        ULONG Reserved;
//        char  Data[0];
//} NP_DATA_QUEUE_ENTRY;
//
//// structs with x in front referes to custom or ones that i do not know abopput that is documented
//typedef struct _xVS_DQE_HEADER_CHUNK {
//    HEAP_VS_CHUNK_HEADER vs_chunk_header; //size 0x10
//	POOL_HEADER pool_header; //size 0x10
//	NP_DATA_QUEUE_ENTRY np_data_queue_entry; //size 0x20
//}xVS_DQE_HEADER_CHUNK, *p_xVS_DQE_HEADER_CHUNK;
