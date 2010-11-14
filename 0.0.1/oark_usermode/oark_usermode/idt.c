#include "idt.h"

int idt( HANDLE device )
{
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

	GetSystemInfo( & sysinfo );

	memset( & kpcr, 0, sizeof( kpcr ) );

	for ( i = 0; i < sysinfo.dwNumberOfProcessors; i++ )
	{
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
			printf( " IDT KPCR: 0x%08X\n", kpcr.IDT );

			read_kern_mem.type        = SYM_TYP_IDT;
			read_kern_mem.dst_address = & idtr_r0;
			read_kern_mem.size        = sizeof( idtr_r0 );
			if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
				printf( " ERROR: IOCTL CHANGE MODE\n" );
			else
			{
				printf
				( 
					" SIDT RING0: 0x%08X, bytes: 0x%X\n", 
					MAKEDWORD( idtr_r0.baseAddressLow, idtr_r0.baseAddressHi ),
					idtr_r0.nBytes
				);

				__asm { sidt idtr_r3 }

				printf
				( 
					" SIDT RING3: 0x%08X, bytes: 0x%X\n", 
					MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi ),
					idtr_r3.nBytes
				);

				if 
				( 
					( memcmp( & idtr_r3, & idtr_r0, sizeof( idtr_r3 ) ) == 0 )
					&&
					( MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi ) == ( (DWORD) kpcr.IDT ) )
				)
				{
					printf( " OK: WITHOUT EMULATION!, IDT DATA OK, USING IDT INSTRUCTION (WITHOUT KPCR)\n" );
					idt_address = (void *) MAKEDWORD( idtr_r3.baseAddressLow, idtr_r3.baseAddressHi );
					idt_size    = idtr_r3.nBytes;
				}
				else
				{
					printf
					( 
						" WARNING: WITH EMULATION!, ERROR IDT DATA, USING KPCR, HARDCODE SIZE: 0x%X\n",
						IDT_HARDCODE_SIZE 
					);
					idt_address = kpcr.IDT;
					idt_size    = IDT_HARDCODE_SIZE;
				}

				printf( " IDT CORE %d, ADDRESS: 0x%08X, SIZE: 0x%X\n\n", i + 1, idt_address, idt_size );

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

						printf
						( 
							" IDT ENTRY: 0x%02X: 0x%08X TYPE GATE: %s\n", 
							j, 
							idt_info,
							type_gate
						);
					}

					( ( IDT_DESCRIPTOR * ) read_kern_mem.src_address )++;
				}
			}
		}
	}

	return returnf;
}