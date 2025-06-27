#include "umac/umac.h"

#include <stdio.h>

int main()
{
	umac_initialize();
	int counter = 0;
	while (1) 
	{
		uint16_t violations = umac_check_regular();

		if (counter >= 128)
		{
			violations |= umac_check_intermittent();
			counter = 0;
		}

		if (violations & UMAC_CHECK_DEBUGGER)
		{
			puts("Debugger Detected");
		}

		if (violations & UMAC_CHECK_HANDLE)
		{
			puts("Open Handle Detected");
		}

		Sleep(50);
		counter++;
	}
	umac_shutdown();
	return 187;
}