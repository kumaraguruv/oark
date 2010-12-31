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

BOOLEAN GetKPCR( KPCR * kpcr, FUNC_ARGS_GLOBAL_t * globals )
{
    READ_KERN_MEM_t read_kern_mem;

    read_kern_mem.type        = SYM_TYP_KPCR;
    read_kern_mem.src_address = NULL;
    read_kern_mem.dst_address = & kpcr;
    read_kern_mem.size        = sizeof( kpcr );

    if ( IOCTLReadKernMem( globals->hdevice, & read_kern_mem ) == NULL )
        return FALSE;

    return TRUE;
}

BOOLEAN GetGDTFromKernel( GDTR * gdt, FUNC_ARGS_GLOBAL_t * globals )
{
    READ_KERN_MEM_t read_kern_mem;

    read_kern_mem.type        = SYM_TYP_GDT;
    read_kern_mem.dst_address = gdt;
    read_kern_mem.size        = sizeof( * gdt );
    if ( IOCTLReadKernMem( globals->hdevice, & read_kern_mem ) == NULL )
        return FALSE;

    return TRUE;
}

BOOLEAN GetGDTFromUserMode( GDTR * gdt, FUNC_ARGS_GLOBAL_t * globals )
{
    __asm { sgdt gdt }

    return TRUE;
}

BOOLEAN GetGDTAddress( GDTR * gdt, DWORD core, FUNC_ARGS_GLOBAL_t * globals )
{
    KPCR kpcr;
    GDTR gdtr_r0, gdtr_r3;
    GDTR * gdt_ret;
    BOOLEAN fkpcr = FALSE, fkernel = FALSE, fusermode = FALSE, checking;

    SetThreadAffinityMask( GetCurrentThread(), 1 << core );
    Sleep( 0 );

    if ( GetKPCR( & kpcr, globals ) )
        fkpcr = TRUE;

    if ( GetGDTFromKernel( & gdtr_r0, globals ) )
        fkernel = TRUE;

    if ( GetGDTFromUserMode( & gdtr_r3, globals ) )
        fusermode = TRUE;

    checking = TRUE;
    if ( fkpcr )
    {
        if ( fkernel )
        {
            if ( (DWORD) kpcr.GDT != gdtr_r0.baseAddress )
                checking = FALSE;
        }

        if ( fusermode )
        {
            if ( (DWORD) kpcr.GDT != gdtr_r3.baseAddress ) 
                checking = FALSE;
        }

        if ( fusermode && fkernel )
        {
            if ( gdtr_r0.nBytes != gdtr_r3.nBytes )
                checking = FALSE;
        }

        if ( checking == FALSE )
        {
            gdt->baseAddress = (DWORD) kpcr.GDT;
            gdt->nBytes = GDT_HARDCODE_SIZE;
        }
    }

    if ( checking )
    {
        if ( fkernel )
            gdt_ret = & gdtr_r0;
        else if ( fusermode )
            gdt_ret = & gdtr_r3;
        else
            return FALSE;

        gdt->baseAddress = gdt_ret->baseAddress;
        gdt->nBytes = gdt_ret->nBytes;
    }

    return TRUE;
}

BOOLEAN GetGDTEntries( GDTR * gdt, PSEG_DESCRIPTOR descriptors, FUNC_ARGS_GLOBAL_t * globals )
{
    READ_KERN_MEM_t read_kern_mem; 

    read_kern_mem.type        = SYM_TYP_NULL;
    read_kern_mem.dst_address = descriptors;
    read_kern_mem.size        = gdt->nBytes;
    read_kern_mem.src_address = (void *) gdt->baseAddress;
    if ( IOCTLReadKernMem( globals->hdevice, & read_kern_mem ) == NULL )
        return FALSE;

    return TRUE;
}

BOOLEAN GetGDTDescriptor( DWORD * types, DWORD types_nr, DWORD core, DESCRIPTOR_t ** descriptors, DWORD * nr, GDTR * gdtout, FUNC_ARGS_GLOBAL_t * globals )
{
    GDTR gdt;
    DWORD i, j, k;
    DWORD type;
    DESCRIPTOR_t * new_descriptors;
    PSEG_DESCRIPTOR raw_descriptors;

    if ( GetGDTAddress( & gdt, core, globals ) )
    {
        * descriptors = calloc( 1, sizeof( ** descriptors ) * ( gdt.nBytes / 8 ) );
        raw_descriptors = calloc( 1, gdt.nBytes );
        if ( * descriptors != NULL && raw_descriptors != NULL )
        {
            if ( GetGDTEntries( & gdt, raw_descriptors, globals ) )
            {
                k = 0;
                for ( i = 0; i < (DWORD) gdt.nBytes / 8; i++ )
                {
                    (* descriptors)[i].descriptor = raw_descriptors[i];
                    (* descriptors)[i].selector = (i + 1) * sizeof( GDTR );

                    if ( types != NULL )
                    {
                        type = (* descriptors)[i].descriptor.type;
                        if( (* descriptors)[i].descriptor.sFlag == 0 )
                            type += 16;
  
                        for ( j = 0; j < types_nr; j++ )
                        {
                            if ( types[j] == type )
                                k++;
                        }
                    }
                }

                * nr = gdt.nBytes / 8;
                if ( gdtout != NULL )
                    memcpy( gdtout, & gdt, sizeof( * gdtout ) );

                free( raw_descriptors );

                if ( types == NULL )
                    return TRUE;

                if ( k > 0 )
                {
                    new_descriptors = calloc( 1, sizeof( * new_descriptors ) * k );
                    if ( new_descriptors != NULL )
                    {
                        k = 0;
                        for ( i = 0; i < (DWORD) gdt.nBytes / 8; i++ )
                        {
                            type = (* descriptors)[i].descriptor.type;
                            if( (* descriptors)[i].descriptor.sFlag == 0 )
                                type += 16;

                            for ( j = 0; j < types_nr; j++ )
                            {
                                if ( types[j] == type )
                                {
                                    new_descriptors[k] = (* descriptors)[i];
                                    k++;
                                }
                            }
                        }

                        free( (* descriptors) );

                        (* descriptors) = new_descriptors;

                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

BOOLEAN GetGDTDescriptors( DWORD * types, DWORD types_nr, DESCRIPTOR_CORE_TAB_WNR_t * descriptor_table, FUNC_ARGS_GLOBAL_t * globals )
{
    SYSTEM_INFO sysinfo;
    unsigned int i;
    DESCRIPTOR_t * descriptor;
    BOOLEAN returnf = FALSE;

    GetSystemInfo( & sysinfo );

    descriptor_table->descriptor_table = calloc( 1, sizeof( * descriptor_table->descriptor_table ) * sysinfo.dwNumberOfProcessors );

    if ( descriptor_table->descriptor_table != NULL )
    {
        descriptor_table->nr = 0;
        for ( i = 0; i < sysinfo.dwNumberOfProcessors; i++ )
        {
            if ( GetGDTDescriptor( types, types_nr, i, & descriptor, & descriptor_table->descriptor_table[descriptor_table->nr].nr, & descriptor_table->descriptor_table[descriptor_table->nr].gdt, globals ) )
            {
                descriptor_table->descriptor_table[descriptor_table->nr].descriptors = descriptor;
                descriptor_table->descriptor_table[descriptor_table->nr].core = i + 1;
 
                descriptor_table->nr++;

                returnf = TRUE;
            }

            if ( returnf == FALSE )
                free( descriptor_table->descriptor_table );
        }
    }
    
    return returnf;
}

void FreeGDTDescriptors( DESCRIPTOR_CORE_TAB_WNR_t * descriptor_table )
{
    DWORD i;

    for ( i = 0; i < descriptor_table->nr; i++ )
        free( descriptor_table->descriptor_table[i].descriptors );

    free( descriptor_table->descriptor_table );
}

STATUS_t CheckCallGates( FUNC_ARGS_t * args, FUNC_ARGS_GLOBAL_t * globals )
{
    TYPES_t types;
    DESCRIPTOR_CORE_TAB_WNR_t descriptor_table;

    if ( InitTypes( args->flags, & types ) )
    {
        if ( GetGDTDescriptors( types.types, types.nr, & descriptor_table, globals ) )
        {
            
            FreeGDTDescriptors( & descriptor_table ); 
        }

        free( types.types );
    }
 
    return ST_OK;
}


BOOLEAN InitTypes( DWORD inflags, TYPES_t * types )
{
    unsigned int i, j;
    FLAG_TABLE_t flags[] =
    { 
        { FIN_CALL_GATES_GDT, CALL_GATE_32_TYPE },
        { FIN_CALL_GATES_LDT, LDT_TYPE }
    };

    types->types = NULL;

    for ( i = 0, j = 0; i < sizeof( flags ) / sizeof( * flags ); i++ )
    {
        if ( inflags & flags[i].flag_param )
            j++;
    }

    if ( j > 0 )
    {
        types->types = calloc( 1, j * sizeof( * types ) );
        if ( types != NULL )
        {
            types->nr = j;
            for ( i = 0; i < sizeof( flags ) / sizeof( * flags ); i++ )
            {
                if ( inflags & flags[i].flag_param )
                    types->types[i] = flags[i].flag_desc;
            }
        }
    } 

    if ( types->types == NULL )
        return FALSE;

    return TRUE;
}