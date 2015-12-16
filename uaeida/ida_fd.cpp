#include <Windows.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>

#include <regex>

#include "ida_fd.h"
#include "sysdeps.h"
#include "memory.h"

void get_fd_func_name(const char *fd_name, int offset, char *buf, size_t buf_len)
{
	const char __public[] = "##public";
	const char __private[] = "##private";
	const char __library[] = ".library";
	
	char name[MAXSTR];
	char line[MAXSTR];

	buf[0] = '\0';
	qsnprintf(name, sizeof(name), "%s\\fd\\%s", idadir("plugins"), fd_name);
	char *dot_ptr = qstrchr(name, '.');
	qstrncpy(dot_ptr, "_lib.fd", qstrlen(__library));

	linput_t *li = open_linput(name, false);

	if (li == NULL)
	{
		warning("Cannot find \"IDA_DIR\\plugins\\fd\\%s.fd\" file!\n", fd_name);
		buf[0] = '\0';
		return;
	}

	int offs = -30;
	bool pub = true;
	int ll = -1;
	while (qlgets(line, sizeof(line), li))
	{
		ll++;
		
		std::string _line = line;
		_line.erase(_line.find_last_not_of(" \n\r\t") + 1);

		qstrlwr(line);
		std::string l(line);
		l.erase(l.find_last_not_of(" \n\r\t") + 1);

		if (l.c_str()[0] == '*')
			continue;
		else if (qstrcmp(l.c_str(), __public) == 0)
			pub = true;
		else if (qstrcmp(l.c_str(), __private) == 0)
			pub = false;

		std::cmatch cm;
		std::regex reg("##bias ([0-9]+)");

		if (std::regex_match(l.c_str(), cm, reg) && cm.size() > 1)
			offs = -std::stoi(cm.str(1));

		reg = "(\\w+)[(]";
		if (std::regex_search(l.c_str(), cm, reg) && cm.size() > 1)
		{
			if (pub && offs == offset)
			{
				qstrncpy(buf, _line.c_str(), buf_len);
				break;
			}

			offs -= 6;
		}
	}

	close_linput(li);
}

void get_fd_lib_name(ea_t ea, char *buf, size_t buf_len)
{
	extern uae_u32 get_long_debug(uaecptr addr);

	buf[0] = '\0';
	qstrncpy(buf, (const char *)((char*)get_real_address(get_long_debug(ea + 10))), buf_len);
}
