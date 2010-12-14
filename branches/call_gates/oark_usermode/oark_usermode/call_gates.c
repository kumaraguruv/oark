/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "call_gates.h"

void CheckCallGatesAndLDTFW( HANDLE device )
{
    SYSTEM_INFO sysinfo;
    unsigned int i, j;
    KPCR            kpcr;
    GDTR            gdtr_r0, gdtr_r3;
    READ_KERN_MEM_t read_kern_mem;
    void * gdt_address;
    DWORD gdt_size;
    SEG_DESCRIPTOR gdt_desc;
    DWORD mm_user_probe_address;

    GetSystemInfo( & sysinfo );

    memset( & kpcr, 0, sizeof( kpcr ) );

    read_kern_mem.type        = SYM_TYP_MM_USR_PRB_ADDR;
    read_kern_mem.dst_address = & mm_user_probe_address;
    read_kern_mem.size        = sizeof( mm_user_probe_address );
    read_kern_mem.src_address = NULL;

    if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
    {
        if ( debug )
            printf( " ERROR: IOCTL CHANGE MODE\n" );
        mm_user_probe_address = 0;
    }
    else
    {
        if ( debug )
            printf( " MM USER PROBE ADDRESS: 0x%08X\n", mm_user_probe_address );
    }

    for ( i = 0; i < sysinfo.dwNumberOfProcessors; i++ )
    {
        if ( debug )
            printf( " Set Thread Affinity Mask to: %d\n", i + 1 );
        SetThreadAffinityMask( GetCurrentThread(), 1 << i );
        Sleep( 0 );

        read_kern_mem.type        = SYM_TYP_KPCR;
        read_kern_mem.src_address = NULL;
        read_kern_mem.dst_address = & kpcr;
        read_kern_mem.size        = sizeof( kpcr );

        if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
            printf( " ERROR: IOCTL CHANGE MODE\n" );
        else
        {
            if ( debug )
                printf( " GDT KPCR: 0x%08X\n", kpcr.GDT );

            read_kern_mem.type        = SYM_TYP_GDT;
            read_kern_mem.dst_address = & gdtr_r0;
            read_kern_mem.size        = sizeof( gdtr_r0 );
            if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
                printf( " ERROR: IOCTL CHANGE MODE\n" );
            else
            {
                if ( debug )
                    printf
                    ( 
                        " SGDT RING0: 0x%08X, bytes: 0x%X\n"
                        , 
                        gdtr_r0.baseAddress,
                        gdtr_r0.nBytes
                    );

                __asm { sgdt gdtr_r3 }

                if ( debug )
                    printf
                        ( 
                        " SGDT RING3: 0x%08X, bytes: 0x%X\n"
                        , 
                        gdtr_r3.baseAddress,
                        gdtr_r3.nBytes
                    );

                if 
                (
                    ( gdtr_r3.baseAddress == gdtr_r0.baseAddress )
                    &&
                    ( gdtr_r3.baseAddress == ( (DWORD) kpcr.GDT ) )
                )
                {
                    if ( debug )
                        printf( " OK: WITHOUT EMULATION!, GDT DATA OK, USING GDT INSTRUCTION (WITHOUT KPCR)\n" );
                    gdt_address = (VOID *) gdtr_r3.baseAddress;
                    gdt_size    = gdtr_r3.nBytes;
                }
                else
                {
                    printf
                    ( 
                        " WARNING: WITH EMULATION!, ERROR GDT DATA, USING KPCR, HARDCODE SIZE: 0x%X\n",
                        GDT_HARDCODE_SIZE 
                    );
                    gdt_address = kpcr.IDT;
                    gdt_size    = GDT_HARDCODE_SIZE;
                }

                if ( debug )
                    printf( " GDT CORE %d, ADDRESS: 0x%08X, SIZE: 0x%X\n\n", i + 1, gdt_address, gdt_size );

                read_kern_mem.type        = SYM_TYP_NULL;
                read_kern_mem.dst_address = & gdt_desc;
                read_kern_mem.size        = sizeof( gdt_desc );
                read_kern_mem.src_address = gdt_address;

                for ( j = 0; j <= ( gdt_size / 8 ); j++ )
                {
                    if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
                        printf( " ERROR: IOCTL CHANGE MODE\n" );
                    else
                        CheckDesc( & gdt_desc, mm_user_probe_address, i + 1, device );

                    ( ( SEG_DESCRIPTOR * ) read_kern_mem.src_address )++;
                }
            }   
        }
    }

}

void FindCallGates( PSEG_DESCRIPTOR descriptor, DWORD nr )
{
    unsigned int i;
    DWORD type;

    for ( i = 0; i < nr; i++ )
    {
        type = descriptor->type;

        if ( descriptor->sFlag == 0 )
            type += 16;

        switch ( type )
        {
            case CALL_GATE_32_TYPE:
                printf( " Call Gate Detected!\n" );
            break;
        }
    }
}

void CheckDesc( PSEG_DESCRIPTOR descriptor, DWORD mm_user_probe_address, DWORD core, HANDLE device )
{
    DWORD base;
    DWORD limit;
    PSEG_DESCRIPTOR ldt_desc;
    DWORD type;
    READ_KERN_MEM_t read_kern_mem;
    
    GetBaseAndLimit( descriptor, & base, & limit );

    type = descriptor->type;
    if ( descriptor->sFlag == 0 )
         type += 16;

    switch ( type )
    {
        case LDT_TYPE:
            if ( debug )
                printf( " LDT IN GDT!\n" );
            
            /* I assume: mm_user_probe_address always is set */
            if ( mm_user_probe_address <= base )
                printf( " POSSIBLE LDT FORWARD TO USER SPACE ATTACK DETECTED!: 0x%08X\n", base );
            else
            {
                if ( debug )
                    printf( " Searching Call Gates in LDT: nr entries: 0x%X\n", ( limit + 1 ) / 8  );
                ldt_desc = calloc \
                        ( 
                            1, 
                            ( ( limit + 1 ) / 8 ) * sizeof( * ldt_desc ) 
                        );
                if ( ldt_desc != NULL )
                {
                    read_kern_mem.type        = SYM_TYP_NULL;
                    read_kern_mem.dst_address = ldt_desc;
                    read_kern_mem.size        = ( ( limit + 1 ) / 8 ) * sizeof( * ldt_desc ) ;
                    read_kern_mem.src_address = (void *) base;

                    if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
                        printf( " ERROR: IOCTL CHANGE MODE\n" );
                    else
                        FindCallGates( ldt_desc, ( limit + 1 ) / 8 );

                    free( ldt_desc );
                }
            }
        break;

        default:
            FindCallGates( descriptor, 1 );
        break;
    }
}


void GetBaseAndLimit( PSEG_DESCRIPTOR pdt, DWORD * base, DWORD * limit )
{
    if ( limit != NULL )
    {
        (* limit) = 0;
        (* limit) = (* limit) + pdt->size_16_19;
        (* limit) = (* limit) << 16;
        (* limit) = (* limit) + pdt->size_00_15;
    }

    if ( base != NULL )
    {
        (* base) = 0;
        (* base) = (* base) + pdt->baseAddress_24_31;
        (* base) = (* base) << 8;
        (* base) = (* base) + pdt->baseAddress_16_23;
        (* base) = (* base) << 16;
        (* base) = (* base) + pdt->baseAddress_00_15;
    }
}