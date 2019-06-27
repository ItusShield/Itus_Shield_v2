--[[

LuCI Snort module

Copyright (C) 2015, Itus Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Author: Luka Perkov <luka@openwrt.org>

Version 4:
Redo some of the system calls and file paths for the updated Firmware

version 3
Modified by Roadrunnere42 added if then statement to choose which mode the shield's in and display in >>services >> intrusion prevention window
either one snort config file or 2 snort config files if running in router mode.

version 2
Modified by Roadrunnere42 to include a tab called priority 1 logs in intrusion prevention window, which displays any IPS rules that has trigger a priority 1 log in the IPS log.
/usr/lib/lua/luci/model/cbi/snort.lua - changed
/tmp/snort/priority1 - added to hold priority 1 logs

version 1
Modified by Roadrunnere42 to include a tab called rule counter in intrusion prevention window, which displays the number of rules that each rule set has.
This requires the following files to be changed or added
/tmp/rule_counter.log                 - created when run
/sbin/fw_upgrade.sh                   - changed
/usr/lib/lua/luci/model/cbi/snort.lua - changed

]]--

local fs = require "nixio.fs"
local sys = require "luci.sys"
require "ubus"

m = Map("snort", translate("Intrusion Prevention"), translate("Changes may take up to 90 seconds to take effect, service may be interrupted during that time. The IPS engine will restart each time you click the Save & Apply or On/Off button."))

m.on_init = function()

    -- Read the SHIELD_MODE envsetup
   if os.getenv("SHIELD_MODE") == "Router" then
      luci.sys.call("sed '1!G;h$!d' /var/log/snort/alert.log > /tmp/snort/alert2.log")
   end
   luci.sys.call("grep -i 'priority: 1' /var/log/snort/alert2.log > /var/log/snort/priority1.log")
end

m.reset = false
m.submit = false

s = m:section(NamedSection, "snort")
s.anonymous = true
s.addremove = false

s:tab("tab_basic", translate("Basic Settings"))
-- Read the SHIELD_MODE envsetup
if os.getenv("SHIELD_MODE") == "Router" then
   s:tab("tab_wan", translate("WAN Config"))
   s:tab("tab_lan", translate("LAN Config"))
else
   s:tab("tab_config", translate("Config"))
end

s:tab("tab_threshold", translate("Threshold Config"))
s:tab("tab_custom", translate("Custom Rules"))
s:tab("tab_rules", translate("Exclude Rules"))
s:tab("tab_logs", translate("IPS Logs"))
s:tab("tab_priority", translate("IPS Priority 1 log"))
s:tab("tab_counter", translate("Rule Counter"))
--s:tab("tab_snort1", translate("Snort Rules Selector"))


--------------------- Basic Tab ------------------------
local status="not running"
require "ubus"
local conn = ubus.connect()
if not conn then
   error("Failed to connect to ubusd")
end

for k, v in pairs(conn:call("service", "list", { name="snort" })) do
   status="running"
end

button_start = s:taboption("tab_basic",Button, "start", translate("Status: "))
  if status == "running" then
   button_start.inputtitle = "ON"
  else
   button_start.inputtitle = "OFF"
  end

  button_start.write = function(self, section)
   if status == "not running" then
      sys.call("service snort start")
      button_start.inputtitle = "ON"
      button_start.title = "Status: "
   else
      sys.call("service snort stop")
      button_start.inputtitle = "OFF"
      button_start.title = "Status: "
   end
  end

  if status == "running" then
   button_restart = s:taboption("tab_basic", Button, "restart", translate("Restart: "))
   button_restart.inputtitle = "Restart"
   button_restart.write = function(self, section)
      sys.call("service snort restart")   
   end
  end

  if os.getenv("SHIELD_MODE") == "Router" then
   --------------------- Snort Instance WAN Tab -----------------------

   config_file1 = s:taboption("tab_wan", TextValue, "text1", "")
   config_file1.wrap = "off"
   config_file1.rows = 25
   config_file1.rmempty = false

   function config_file1.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort7.conf"
      if file then
         return fs.readfile(file) or ""
      else
         return ""
      end
   end

   function config_file1.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
	       file = "/etc/snort/snort7.conf"
	       fs.writefile(file, value:gsub("\r\n", "\n"))
	       luci.sys.call("/etc/init.d/snort restart")
      end
   end
   ---------------------- Snort Instance LAN Tab ------------------------

   config_file2 = s:taboption("tab_lan", TextValue, "text2", "")
   config_file2.wrap = "off"
   config_file2.rows = 25
   config_file2.rmempty = false

   function config_file2.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort8.conf"
      if file then
         return fs.readfile(file) or ""
      else
         return ""
      end
   end

   function config_file2.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
	 file = "/etc/snort/snort8.conf"
	 fs.writefile(file, value:gsub("\r\n", "\n"))
	 luci.sys.call("/etc/init.d/snort restart")
      end
   end

   else
   ---------------------- Snort Config Tab ------------------------

   config_file2 = s:taboption("tab_config", TextValue, "config1", "")
   config_file2.wrap = "off"
   config_file2.rows = 25
   config_file2.rmempty = false

   function config_file2.cfgvalue()
      local uci = require "luci.model.uci".cursor_state()
      file = "/etc/snort/snort_bridge.conf"
      if file then
         return fs.readfile(file) or ""
      else
	       return ""
      end
   end

   function config_file2.write(self, section, value)
      if value then
         local uci = require "luci.model.uci".cursor_state()
         file = "/etc/snort/snort_bridge.conf"
         fs.writefile(file, value:gsub("\r\n", "\n"))
         luci.sys.call("/etc/init.d/snort restart")
      end
   end
end

	---------------------- Threshold Config Tab ------------------------

	config_file2 = s:taboption("tab_threshold", TextValue, "threshold", "")
	config_file2.wrap = "off"
	config_file2.rows = 25
	config_file2.rmempty = false

	function config_file2.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/threshold.conf"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file2.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/threshold.conf"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
		end
	end

	---------------------- Custom Rules Tab ------------------------

	config_file2 = s:taboption("tab_custom", TextValue, "text3", "")
	config_file2.wrap = "off"
	config_file2.rows = 25
	config_file2.rmempty = false

	function config_file2.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/local.rules"
		if file then
			return fs.readfile(file) or ""
		else
			return ""
		end
	end

	function config_file2.write(self, section, value)
		if value then
			local uci = require "luci.model.uci".cursor_state()
			file = "/etc/snort/rules/local.rules"
			fs.writefile(file, value:gsub("\r\n", "\n"))
			luci.sys.call("/etc/init.d/snort restart")
		end
	end

	--------------------- Exclude Rules Tab ------------------------

	config_file5 = s:taboption("tab_rules", TextValue, "text4", "")
	config_file5.wrap = "off"
	config_file5.rows = 25
	config_file5.rmempty = false

	function config_file5.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/exclude.rules"
		if file then
		return fs.readfile(file) or ""
	else
		return ""
	end
end

function config_file5.write(self, section, value)
	if value then
		local uci = require "luci.model.uci".cursor_state()
		file = "/etc/snort/rules/exclude.rules"
		fs.writefile(file, value:gsub("\r\n", "\n"))
		luci.sys.call("/etc/init.d/snort restart")
	end
end

		--------------------- Logs Tab ------------------------

	snort_logfile = s:taboption("tab_logs", TextValue, "logfile", "")
	snort_logfile.wrap = "off"
	snort_logfile.rows = 25
	snort_logfile.rmempty = false

	function snort_logfile.cfgvalue()
		local uci = require "luci.model.uci".cursor_state()
		local file = "/tmp/snort/alert2"
		if file then
		return fs.readfile(file) or ""
		else
		return ""
		end
	end

	---------------------Priority Tab ------------------------
snort_logfile1 = s:taboption("tab_priority", TextValue, "IPS priority 1 log", "")
snort_logfile1.wrap = "off"
snort_logfile1.rows = 25
snort_logfile1.rmempty = false

function snort_logfile1.cfgvalue()
			local uci = require "luci.model.uci".cursor_state()
			local file = "/tmp/snort/priority1"
				if file then
								return fs.readfile(file) or ""
				else
								return ""
				end
end

	--------------------- counter Tab ------------------------

	counter = s:taboption("tab_counter", TextValue, "Counter", "")
	counter.wrap = "off"
	counter.rows = 25
	counter.rmempty = false

	function counter.cfgvalue()
				local uci = require "luci.model.uci".cursor_state()
				local file = "/tmp/rule_counter.log"
					if file then
									return fs.readfile(file) or ""
					else
									return ""
					end
	end

	--------------------- snort rule selector Tab ------------------------


--	firefox = s:taboption("tab_snort1", Flag, "content_firefox", translate("Firefox"))
-- firefox.default=firefox.disabled
--	firefox.rmempty = false

	--firefox = s:taboption("tab_snort1", Flag, "content_firefox", translate("Firefox"))
--	firefox.default=snort1.enabled
--	firefox.rmempty = false








return m
