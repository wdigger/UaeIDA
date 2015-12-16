#include <Windows.h>

#include <ida.hpp>
#include <dbg.hpp>
#include <loader.hpp>

#include "ida_plugin.h"
#include "ida_fd.h"
#define VERSION "1.0.0"

extern debugger_t debugger;

static bool plugin_inited;
static bool dbg_started;

static int idaapi hook_dbg(void *user_data, int notification_code, va_list va)
{
	switch (notification_code)
	{
	case dbg_notification_t::dbg_process_start:
		dbg_started = true;
		break;

	case dbg_notification_t::dbg_process_exit:
		dbg_started = false;
		break;
	}
	return 0;
}

//--------------------------------------------------------------------------
static void print_version()
{
	static const char format[] = NAME " debugger plugin v%s;\nAuthor: Dr. MefistO [Lab 313] <meffi@lab313.ru>.";
	info(format, VERSION);
	msg(format, VERSION);
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static bool init_plugin(void)
{
	if (ph.id != PLFM_68K)
		return false;

	return true;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
	if (init_plugin())
	{
		dbg = &debugger;
		plugin_inited = true;
		dbg_started = false;

		hook_to_notification_point(HT_DBG, hook_dbg, NULL);
		print_version();
		return PLUGIN_KEEP;
	}
	return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
	if (plugin_inited)
	{
		//term_plugin();
		unhook_from_notification_point(HT_DBG, hook_dbg, NULL);
		plugin_inited = false;
		dbg_started = false;
	}
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static void idaapi run(int /*arg*/)
{
	ea_t ea = get_screen_ea();
	if (dbg_started && isEnabled(ea)) // address belongs to disassembly
	{
		if (decode_insn(ea))
		{
			if (cmd.itype == 0x75) // jsr
			{
				if (cmd.Op1.type == o_displ &&
					cmd.Op1.dtyp == dt_word &&
					cmd.Op1.flags == OF_SHOW &&
					cmd.Op1.reg == 0xE) // a6
				{
					char fd_name[256], func_name[256], cmt[256];

					regval_t reg;
					const char *reg_name = dbg->registers(8 /*Dx*/ + 6 /*a6*/).name;

					if (get_reg_val(reg_name, &reg))
					{
						get_fd_lib_name(reg.ival, fd_name, sizeof(fd_name));

						if (fd_name[0] != '\0')
						{
							get_fd_func_name(fd_name, cmd.Op1.addr, func_name, sizeof(func_name));

							if (func_name[0] != '\0')
							{
								qsnprintf(cmt, sizeof(cmt), "%s->%s", fd_name, func_name);

								set_cmt(ea, cmt, false);
							}
						}
					}
				}
			}
		}
	}
}

//--------------------------------------------------------------------------
char comment[] = NAME " debugger plugin by Dr. MefistO.";

char help[] =
NAME " debugger plugin by Dr. MefistO.\n"
"\n"
"This module lets you debug Amiga hunks in IDA.\n";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	/*PLUGIN_HIDE |*/ PLUGIN_DBG | PLUGIN_MOD, // plugin flags
	init, // initialize

	term, // terminate. this pointer may be NULL.

	run, // invoke plugin

	comment, // long comment about the plugin
			 // it could appear in the status line
			 // or as a hint

	help, // multiline help about the plugin

	NAME " debugger plugin", // the preferred short name of the plugin

	"W" // the preferred hotkey to run the plugin
};
