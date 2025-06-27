#include "umac/umac.h"

#include <stdio.h>

int main()
{
	umac_initialize();
	while (1) 
	{
		uint16_t violations = umac_check_regular();

		if (violations & UMAC_CHECK_DEBUGGER)
		{
			puts("Debugger Detected");
		}

		if (violations & UMAC_CHECK_HANDLE)
		{
			puts("Open Handle Detected");
		}

		Sleep(50);
	}
	umac_shutdown();
	return 187;
}