--[[

LuCI Snort module

Copyright (C) 2015, Itus Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Author: Luka Perkov <luka@openwrt.org>

]]--

local fs = require "nixio.fs"
local sys = require "luci.sys"
require "ubus"

m = Map("snort", translate("Intrusion Prevention"), translate("Advanced mode may take a few minutes to load. Changes may take up to 90 seconds to take effect, service may be interrupted during that time."))

m.on_init = function()
--	luci.sys.call("/etc/init.d/snort restart")
--	luci.sys.call("/etc/snort/exclude_rule.sh")
end

m.reset = false
m.submit = false

s = m:section(NamedSection, "snort")
s.anonymous = true
s.addremove = false

s:tab("tab_basic", translate("Basic Settings"))
s:tab("tab_advanced", translate("Advanced Settings"))
s:tab("tab_engine", translate("Engine"))
s:tab("tab_preprocessors", translate("Preprocessors"))
s:tab("tab_other", translate("Other Settings"))
s:tab("tab_rules", translate("Rules"))
s:tab("tab_logs", translate("Logs"))


--------------------- Basic Tab ------------------------

local status="not running"
require "ubus"
local conn = ubus.connect()
if not conn then
        error("Failed to connect to ubusd")
end

for k, v in pairs(conn:call("service", "list", { name="snort" })) do
--for k, v in pairs(conn:call("service", "list", { name="suricata" })) do
        status="running"
end

button = s:taboption("tab_basic",Button, "start", translate("Status: "))
if status == "running" then
        button.inputtitle = "ON"
else
        button.inputtitle = "OFF"
end
button.write = function(self, section)
        if status == "not running" then
                sys.call("/etc/init.d/snort start >/dev/null")
--                sys.call("/etc/init.d/suricata start >/dev/null")
                button.inputtitle = "ON"
                button.title = "Status: "
        else
                sys.call("/etc/init.d/snort stop >/dev/null")
--                sys.call("/etc/init.d/suricata stop >/dev/null")
                button.inputtitle = "OFF"
                button.title = "Status: "
        end
end


profile = s:taboption("tab_basic", ListValue, "profile", translate("Profile: "))
--profile:value("default",  translate("default"))
profile:value("snort",  translate("snort"))
--profile:value("snort-afp",  translate("snort-afp"))
--profile:value("suricata",  translate("suricata"))
profile.default = "snort"

--interface = s:taboption("tab_basic", Value, "interface", translate("Default interface: "))
--interface.datatype = "string"
--interface.placeholder = "eth0"
--interface.default = "eth0"
--interface.rmempty = false

--------------------- Advanced Tab -----------------------

io.input("/etc/itus/advanced.conf")
line = io.read("*line")

if line == "yes" then

	config_file1 = s:taboption("tab_advanced", TextValue, "text1", "")
	config_file1.wrap = "off"
	config_file1.rows = 25
	config_file1.rmempty = false

	function config_file1.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config1_advanced.conf"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file1.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/profile/config1_advanced.conf"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
--			luci.sys.call("/etc/init.d/suricata restart")
		end
	end

	---------------------- Engine Tab ------------------------

	config_file2 = s:taboption("tab_engine", TextValue, "text2", "")
	config_file2.wrap = "off"
	config_file2.rows = 25
	config_file2.rmempty = false

	function config_file2.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config2_engine.conf"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file2.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/profile/config2_engine.conf"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
--			luci.sys.call("/etc/init.d/suricata restart")
		end
	end

	------------------- Preprocessors Tab ---------------------

	config_file3 = s:taboption("tab_preprocessors", TextValue, "text3", "")
	config_file3.wrap = "off"
	config_file3.rows = 25
	config_file3.rmempty = false

	function config_file3.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config3_preprocessors.conf"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file3.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/profile/config3_preprocessors.conf"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
--			luci.sys.call("/etc/init.d/suricata restart")  
		end
	end
----DANIEL added luci.sys.call("/etc/init.d/snort restart") here

	--------------------- Other Tab ------------------------

	config_file4 = s:taboption("tab_other", TextValue, "text4", "")
	config_file4.wrap = "off"
	config_file4.rows = 25
	config_file4.rmempty = false

	function config_file4.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/profile/config4_other.conf"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file4.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/profile/config4_other.conf"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
--			luci.sys.call("/etc/init.d/suricata restart")
		end
	end
----DANIEL added luci.sys.call("/etc/init.d/snort restart") here
	--------------------- Rules Tab ------------------------

	config_file5 = s:taboption("tab_rules", TextValue, "text5", "")
	config_file5.wrap = "off"
	config_file5.rows = 25
	config_file5.rmempty = false

	function config_file5.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/snort.rules"
--		file = "/etc/suricata/rules/suri.rules"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file5.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/rules/snort.rules"
--			file = "/etc/suricata/rules/suri.rules"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
--			luci.sys.call("/etc/init.d/suricata restart")
		end
	end
end
----DANIEL added luci.sys.call("/etc/init.d/snort restart") here
--------------------- Logs Tab ------------------------

snort_logfile = s:taboption("tab_logs", TextValue, "logfile", "")
snort_logfile.wrap = "off"
snort_logfile.rows = 20
snort_logfile.rmempty = true

function snort_logfile.cfgvalue()
        local uci = require "luci.model.uci".cursor_state()
        local file = "/var/log/snort/alert.log"
        if file then
                return fs.readfile(file) or ""
        else
                return ""
        end
end

--exclude = s:taboption("tab_logs", Value, "exclude", "Rule to exclude: ", translate(""))
--exclude.wrap = "on"
--exclude.rmempty = true
--exclude.placeholder = ""

return m	
