#include <Windows.h>

#include <ida.hpp>
#include <dbg.hpp>
#include <diskio.hpp>

#define get_long get_long_
#define get_word get_word_
#define get_byte get_byte_
#define put_byte put_byte_

#include "ida_plugin.h"
#include "ida_debmod.h"

#include "sysconfig.h"
#include "sysdeps.h"
#include "options.h"
#include "memory.h"
#include "custom.h"
#include "newcpu.h"
#include "debug.h"
#include "uae.h"

int PASCAL wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow);

eventlist_t g_events;
qthread_t uae_thread = NULL;

#define REGS_GENERAL 1
#define REGS_OTHERS  2
static const char *register_classes[] =
{
	"General Registers",
	NULL
};

static const char *const SRReg[] =
{
	"C",
	"V",
	"Z",
	"N",
	"X",
	NULL,
	NULL,
	NULL,
	"I",
	"I",
	"I",
	NULL,
	NULL,
	"S",
	NULL,
	"T"
};

register_info_t registers[] =
{
	{ "D0", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D1", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D2", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D3", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D4", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D5", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D6", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "D7", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A0", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A1", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A2", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A3", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A4", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A5", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A6", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },
	{ "A7", REGISTER_ADDRESS, REGS_GENERAL, dt_dword, NULL, 0 },

	{ "PC", REGISTER_ADDRESS | REGISTER_IP, REGS_GENERAL, dt_dword, NULL, 0 },

	{ "SR", NULL, REGS_GENERAL, dt_word, SRReg, 0xFFFF },
};

/// Initialize debugger.
/// This function is called from the main thread.
/// \return success
static bool idaapi init_debugger(const char *hostname, int portnum, const char *password)
{
	return true;
}

/// Terminate debugger.
/// This function is called from the main thread.
/// \return success
static bool idaapi term_debugger(void)
{
	return true;
}

/// Return information about the n-th "compatible" running process.
/// If n is 0, the processes list is reinitialized.
/// This function is called from the main thread.
/// \retval 1  ok
/// \retval 0  failed
/// \retval -1 network error
static int idaapi process_get_info(int n, process_info_t *info)
{
	return 0;
}

HINSTANCE GetHInstance()
{
	MEMORY_BASIC_INFORMATION mbi;
	SetLastError(ERROR_SUCCESS);
	VirtualQuery(GetHInstance, &mbi, sizeof(mbi));

	return (HINSTANCE)mbi.AllocationBase;
}
static int idaapi uae_process(void *ud)
{
	SetCurrentDirectoryA(idadir("plugins"));

	wWinMain(GetHInstance(), (HINSTANCE)NULL, L"", SW_NORMAL);

	return 0;
}

static void process_pause()
{
	activate_debugger();
	//close_console();
}

static void process_continue()
{
	deactivate_debugger();
	close_console();
}

static void process_exit()
{
	uae_quit();
	deactivate_debugger();
}

extern int skipaddr_doskip;
extern int no_trace_exceptions;
static void process_step_into()
{
	set_special(SPCFLAG_BRK);
	skipaddr_doskip = 1;
	exception_debugging = 1;
	no_trace_exceptions = 0;
}

/// Start an executable to debug.
/// This function is called from debthread.
/// \param path              path to executable
/// \param args              arguments to pass to executable
/// \param startdir          current directory of new process
/// \param dbg_proc_flags    \ref DBG_PROC_
/// \param input_path        path to database input file.
///                          (not always the same as 'path' - e.g. if you're analyzing
///                          a dll and want to launch an executable that loads it)
/// \param input_file_crc32  CRC value for 'input_path'
/// \retval  1                    ok
/// \retval  0                    failed
/// \retval -2                    file not found (ask for process options)
/// \retval  1 | #CRC32_MISMATCH  ok, but the input file crc does not match
/// \retval -1                    network error
extern char proc_name[2048];
static int idaapi start_process(const char *path, const char *args, const char *startdir, int dbg_proc_flags, const char *input_path, uint32 input_file_crc32)
{
	g_events.clear();

	qstrncpy(proc_name, args, sizeof(proc_name));

	uae_thread = qthread_create(uae_process, NULL);

	return 1;
}

/// Rebase database if the debugged program has been rebased by the system.
/// This function is called from the main thread.
static void idaapi rebase_if_required_to(ea_t new_base)
{
	rebase_program(new_base, MSF_FIXONCE);
}

/// Prepare to pause the process.
/// Normally the next get_debug_event() will pause the process
/// If the process is sleeping then the pause will not occur
/// until the process wakes up. The interface should take care of
/// this situation.
/// If this function is absent, then it won't be possible to pause the program.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
static int idaapi prepare_to_pause_process(void)
{
	process_pause();
	return 1;
}

/// Stop the process.
/// May be called while the process is running or suspended.
/// Must terminate the process in any case.
/// The kernel will repeatedly call get_debug_event() and until ::PROCESS_EXIT.
/// In this mode, all other events will be automatically handled and process will be resumed.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
static int idaapi uae_exit_process(void)
{
	process_exit();
	return 1;
}

/// Get a pending debug event and suspend the process.
/// This function will be called regularly by IDA.
/// This function is called from debthread.
/// IMPORTANT: commdbg does not expect immediately after a BPT-related event
/// any other event with the same thread/IP - this can cause erroneous
/// restoring of a breakpoint before resume
/// (the bug was encountered 24.02.2015 in pc_linux_upx.elf)
static gdecode_t idaapi get_debug_event(debug_event_t *event, int timeout_ms)
{
	while (true)
	{
		// are there any pending events?
		if (g_events.retrieve(event))
		{
			if (event->eid != STEP && event->eid != PROCESS_SUSPEND && event->eid != PROCESS_EXIT)
				process_pause();
			return g_events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
		}
		if (g_events.empty())
			break;
	}
	return GDE_NO_EVENT;
}

/// Continue after handling the event.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
static int idaapi continue_after_event(const debug_event_t *event)
{
	if (event->eid != PROCESS_START)
		process_continue();
	return 1;
}

/// This function will be called by the kernel each time
/// it has stopped the debugger process and refreshed the database.
/// The debugger module may add information to the database if it wants.
///
/// The reason for introducing this function is that when an event line
/// LOAD_DLL happens, the database does not reflect the memory state yet
/// and therefore we can't add information about the dll into the database
/// in the get_debug_event() function.
/// Only when the kernel has adjusted the database we can do it.
/// Example: for imported PE DLLs we will add the exported function
/// names to the database.
///
/// This function pointer may be absent, i.e. NULL.
/// This function is called from the main thread.
static void idaapi stopped_at_debug_event(bool dlls_added)
{

}

/// \name Threads
/// The following functions manipulate threads.
/// These functions are called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
//@{
static int idaapi thread_suspend(thid_t tid)
{
	return 0;
}

static int idaapi thread_continue(thid_t tid)
{
	return 0;
}

static int idaapi uae_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
	switch (resmod)
	{
	case RESMOD_INTO:
		process_step_into();
		break;
	}

	return 1;
}

/// Read thread registers.
/// This function is called from debthread.
/// \param tid      thread id
/// \param clsmask  bitmask of register classes to read
/// \param regval   pointer to vector of regvals for all registers.
///                 regval is assumed to have debugger_t::registers_size elements
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
static int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
	if (clsmask & REGS_GENERAL)
	{
		for (int i = 0; i < 8; ++i)
		{
			values[i].ival = m68k_dreg(regs, i);
		}
		for (int i = 8; i < 16; ++i)
		{
			values[i].ival = m68k_areg(regs, i);
		}
		values[16].ival = m68k_getpc();
		values[17].ival = regs.sr;
	}

	return 1;
}

/// Write one thread register.
/// This function is called from debthread.
/// \param tid     thread id
/// \param regidx  register index
/// \param regval  new value of the register
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
static int idaapi write_register(thid_t tid, int regidx, const regval_t *value)
{
	if (regidx >= 0 && regidx < 8)
		m68k_dreg(regs, regidx) = (uae_u32)value->ival;
	else if (regidx >= 8 && regidx < 16)
		m68k_areg(regs, regidx) = (uae_u32)value->ival;
	else if (regidx == 16)
		m68k_setpc((uaecptr)value->ival);
	else if (regidx == 17)
		regs.sr = (uae_u16)value->ival;
	return 1;
}

/// Get information on the memory areas.
/// The debugger module fills 'areas'. The returned vector MUST be sorted.
/// This function is called from debthread.
/// \retval  -3  use idb segmentation
/// \retval  -2  no changes
/// \retval  -1  the process does not exist anymore
/// \retval   0  failed
/// \retval   1  new memory layout is returned
static int idaapi get_memory_info(meminfo_vec_t &areas)
{
	memory_info_t info;
	info.name = "MEMORY";
	info.startEA = 0x00000000;
	info.endEA = info.startEA + 0xFFFFFF + 1;
	info.bitness = 1;
	areas.push_back(info);

	return 1;
}

/// Read process memory.
/// Returns number of read bytes.
/// This function is called from debthread.
/// \retval 0  read error
/// \retval -1 process does not exist anymore
extern int safe_addr(uaecptr addr, int size);
static ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
	show_wait_box("HIDECANCEL\nReading memory...");
	for (size_t i = 0; i < size; ++i)
	{
		uae_u8 v = 0;
		if (safe_addr(ea + i, 1))
			v = byteget(ea + i);
		((uae_u8*)buffer)[i] = v;
	}
	hide_wait_box();

	return size;
}

/// Write process memory.
/// This function is called from debthread.
/// \return number of written bytes, -1 if fatal error
static ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		uae_u8 v = ((uae_u8*)buffer)[i];
		if (safe_addr(ea + i, 1))
			byteput(ea + i, v);
	}

	return size;
}

/// Is it possible to set breakpoint?.
/// This function is called from debthread or from the main thread if debthread
/// is not running yet.
/// It is called to verify hardware breakpoints.
/// \return ref BPT_
static int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	return BPT_OK;
}

/// Add/del breakpoints.
/// bpts array contains nadd bpts to add, followed by ndel bpts to del.
/// This function is called from debthread.
/// \return number of successfully modified bpts, -1 if network error
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	return (nadd + ndel);
}

//--------------------------------------------------------------------------
//
//	  DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

debugger_t debugger =
{
	IDD_INTERFACE_VERSION, // Expected kernel version
	NAME, // Short debugger name
	321,

	"68000", // Required processor name

	DBG_FLAG_NOHOST | DBG_FLAG_HWDATBPT_ONE | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_CLEAN_EXIT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPASSWORD | DBG_FLAG_ANYSIZE_HWBPT,

	register_classes, // Array of register class names
	REGS_GENERAL, // Mask of default printed register classes
	registers, // Array of registers
	qnumber(registers),

	0x1000, // Size of a memory page

	NULL, // Array of bytes for a breakpoint instruction
	0, // Size of this array
	0, // for miniidbs: use this value for the file type after attaching

	DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER | DBG_RESMOD_STEP_OUT | DBG_RESMOD_STEP_USER,

	init_debugger,
	term_debugger,

	process_get_info,

	start_process,
	NULL, // attach_process
	NULL, // detach_process

	rebase_if_required_to,
	prepare_to_pause_process,
	uae_exit_process,

	get_debug_event,
	continue_after_event,

	NULL, // set_exception_info
	stopped_at_debug_event,

	thread_suspend,
	thread_continue,
	uae_set_resume_mode,

	read_registers,
	write_register,

	NULL, // thread_get_sreg_base

	get_memory_info,
	read_memory,
	write_memory,

	is_ok_bpt,
	update_bpts,
};
