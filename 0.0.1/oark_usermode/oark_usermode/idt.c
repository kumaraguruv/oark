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

#include "idt.h"
#include "render.h"

int idt( HANDLE device )
{
    PREPORT_SUBSECTION *idSubSec = NULL;
    PREPORT_SECTION idSectIdt = NULL;
	int    returnf = -1;
	READ_KERN_MEM_t read_kern_mem;
	KPCR            kpcr;
	IDTR            idtr_r0, idtr_r3;
	void            * idt_address;
	DWORD             idt_size;
	SYSTEM_INFO sysinfo;
	unsigned int i, j;
	IDT_DESCRIPTOR idt_desc;
	char * type_gate;
	DWORD idt_info;

    idSectIdt = RenderAddSection("IDT Information");
	GetSystemInfo( & sysinfo );

	memset( & kpcr, 0, sizeof( kpcr ) );
    idSubSec = malloc(sizeof(PREPORT_SUBSECTION) * sysinfo.dwNumberOfProcessors);
    if(idSubSec == NULL)
    {
        OARK_ALLOCATION_ERROR();
        return 0;
    }

	for ( i = 0; i < sysinfo.dwNumberOfProcessors; i++ )
	{
        idSubSec[i] = RenderAddSubSection(idSectIdt, "IDT Entries");
        RenderAddSeparator(idSubSec[i]);

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
			//printf( " IDT KPCR: 0x%08X\n", kpcr.IDT );

			read_kern_mem.type        = SYM_TYP_IDT;
			read_kern_mem.dst_address = & idtr_r0;
			read_kern_mem.size        = sizeof( idtr_r0 );
			if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
				printf( " ERROR: IOCTL CHANGE MODE\n" );
			else
			{
                /*
				printf
				( 
					" SIDT RING0: 0x%08X, bytes: 0x%X\n", 
					MAKEDWORD( idtr_r0.baseAddressLow, idtr_r0.baseAddressHi ),
					idtr_r0.nBytes
				);
                */

				__asm { sidt idtr_r3 }
                
                /*
				printf
				( 
					" SIDT RING3: 0x%08X, bytes: 0x%X\n", 
					MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi ),
					idtr_r3.nBytes
				);
                */

				if 
				( 
					( memcmp( & idtr_r3, & idtr_r0, sizeof( idtr_r3 ) ) == 0 )
					&&
					( MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi ) == ( (DWORD) kpcr.IDT ) )
				)
				{
					//printf( " OK: WITHOUT EMULATION!, IDT DATA OK, USING IDT INSTRUCTION (WITHOUT KPCR)\n" );
					idt_address = (void *) MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi );
					idt_size    = idtr_r3.nBytes;
				}
				else
				{
                    /*
					printf
					( 
						" WARNING: WITH EMULATION!, ERROR IDT DATA, USING KPCR, HARDCODE SIZE: 0x%X\n",
						IDT_HARDCODE_SIZE 
					);
                    */
					idt_address = kpcr.IDT;
					idt_size    = IDT_HARDCODE_SIZE;
				}

                RenderAddEntry(idSectIdt, "Core Id", i + 1, FORMAT_DEC);
                RenderAddEntry(idSectIdt, "Address", idt_address, FORMAT_HEX);
                RenderAddEntry(idSectIdt, "Size", idt_size, FORMAT_HEX);
                RenderAddSeparator(idSectIdt);

				//printf( " IDT CORE %d, ADDRESS: 0x%08X, SIZE: 0x%X\n\n", i + 1, idt_address, idt_size );

				read_kern_mem.type        = SYM_TYP_NULL;
				read_kern_mem.dst_address = & idt_desc;
				read_kern_mem.size        = sizeof( idt_desc );
				read_kern_mem.src_address = idt_address;
				for ( j = 0; j <= ( idt_size / 8 ); j++ )
				{
					if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
						printf( " ERROR: IOCTL CHANGE MODE\n" );
					else
					{
						idt_info = MAKEDWORD( idt_desc.offset00_15, idt_desc.offset16_31 );
						switch ( idt_desc.gateType )
						{
							case 0x5:
								type_gate = "Task gate";
								idt_info = idt_desc.selector;
							break;

							case 0x6:
								type_gate = "16bit interrupt gate";
							break;

							case 0x7:
								type_gate = "16bit trap gate";
							break;

							case 0xE:
								type_gate = "32bit interrupt gate";
							break;

							case 0xF:
								type_gate = "32bit trap gate";
							break;

							default:
								type_gate = "-";
							break;
						}
                        /*
						printf
						( 
							" IDT ENTRY: 0x%02X: 0x%08X TYPE GATE: %s\n", 
							j, 
							idt_info,
							type_gate
						);
                        */

                        RenderAddEntry(idSubSec[i], "Entry Id", j, FORMAT_DEC);
                        RenderAddEntry(idSubSec[i], "Address", idt_info, FORMAT_HEX);
                        RenderAddEntry(idSubSec[i], "Type Gate", type_gate, FORMAT_STR_ASCII);
                        RenderAddSeparator(idSubSec[i]);
					}

					( ( IDT_DESCRIPTOR * ) read_kern_mem.src_address )++;
				}
			}
		}
	}
    free(idSubSec);
	return returnf;
}